package llmpool

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// rawProvider allows silent EOF, cancellation races and caller-stop cases that
// the ordinary fakeProv (which always emits message_stop) cannot represent.
type rawProvider struct {
	stream func(context.Context) iter.Seq2[llm.StreamEvent, error]
	calls  int
}

func (p *rawProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.calls++
	return p.stream(ctx)
}
func (p *rawProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	for _, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
	}
	return llm.Message{}, "", llm.Usage{}, nil
}

func TestSilentEOFOnlyFailsOverBeforeOutput(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "partial tool call"}[partial], func(t *testing.T) {
			a := &rawProvider{stream: func(context.Context) iter.Seq2[llm.StreamEvent, error] {
				return func(yield func(llm.StreamEvent, error) bool) {
					if partial {
						yield(llm.StreamEvent{Type: llm.SEToolUseStart}, nil)
					}
				}
			}}
			b := okProv("backup", "recovered")
			reg := NewRegistry(nil, nil)
			reg.SetPolicy(1, 0)
			p := New([]*Member{member(1, "primary", 10, a), member(2, "backup", 5, b)}, reg)
			text, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
			if partial {
				if !errors.Is(err, ErrIncompleteStream) || b.calls != 0 {
					t.Fatalf("partial stream replayed: %v calls=%d", err, b.calls)
				}
			} else if err != nil || text != "recovered" || b.calls != 1 {
				t.Fatalf("empty stream did not fail over: %q %v", text, err)
			}
			if !reg.IsOpen(1) {
				t.Fatal("silent EOF did not affect health")
			}
		})
	}
}

func TestMidstreamFailuresTripWithoutReplay(t *testing.T) {
	a := &fakeProv{events: [][]llm.StreamEvent{{{Type: llm.SETextDelta, Text: "partial"}}}, errs: []error{errors.New("connection reset")}}
	b := okProv("backup", "fallback")
	reg := NewRegistry(nil, nil)
	reg.SetPolicy(2, 0)
	p := New([]*Member{member(1, "primary", 10, a), member(2, "backup", 5, b)}, reg)
	for range 2 {
		text, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
		if text != "partial" || err == nil || b.calls != 0 {
			t.Fatalf("unsafe replay: %q %v calls=%d", text, err, b.calls)
		}
	}
	if !reg.IsOpen(1) {
		t.Fatal("repeated midstream errors did not trip health")
	}
	text, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
	if err != nil || text != "fallback" || a.calls != 2 {
		t.Fatal("future call did not skip broken backend")
	}
}

func TestRequestErrorDoesNotEraseHealth(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		reg := NewRegistry(nil, nil)
		reg.Trip(1, "previous failure", false)
		p := New([]*Member{member(1, "a", 10, failProv("a", 400))}, reg)
		if streaming {
			_, _ = drain(p.Stream(context.Background(), llm.CompletionRequest{}))
		} else {
			_, _, _, _ = p.Complete(context.Background(), llm.CompletionRequest{})
		}
		if reg.Get(1).Fails != 1 {
			t.Fatal("request error reset health")
		}
	}
}

func TestCancelledRequestsNeverStartProviders(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		a := okProv("a", "must not execute")
		reg := NewRegistry(nil, nil)
		reg.Trip(1, "previous failure", false)
		p := New([]*Member{member(1, "a", 10, a)}, reg)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var err error
		if streaming {
			_, err = drain(p.Stream(ctx, llm.CompletionRequest{}))
		} else {
			_, _, _, err = p.Complete(ctx, llm.CompletionRequest{})
		}
		if !errors.Is(err, context.Canceled) || a.calls != 0 || reg.Get(1).Fails != 1 {
			t.Fatal("cancel started provider or altered health", err, a.calls)
		}
	}
}

func TestStreamSelectsHealthyBackendWhenConsumed(t *testing.T) {
	a, b := okProv("a", "A"), okProv("b", "B")
	reg := NewRegistry(nil, nil)
	p := New([]*Member{member(1, "a", 10, a), member(2, "b", 5, b)}, reg)
	stream := p.Stream(context.Background(), llm.CompletionRequest{})
	reg.Trip(1, "no credit", true)
	text, err := drain(stream)
	if err != nil || text != "B" || a.calls != 0 {
		t.Fatal("used stale health captured when iterator was created")
	}
}

func TestExhaustionPreservesOriginalCause(t *testing.T) {
	cause := errors.New("transport sentinel")
	for _, streaming := range []bool{false, true} {
		a := &fakeProv{errs: []error{cause}}
		p := New([]*Member{member(1, "a", 10, a)}, nil)
		var err error
		if streaming {
			_, err = drain(p.Stream(context.Background(), llm.CompletionRequest{}))
		} else {
			_, _, _, err = p.Complete(context.Background(), llm.CompletionRequest{})
		}
		if !errors.Is(err, ErrExhausted) || !errors.Is(err, cause) {
			t.Fatalf("lost cause: %v", err)
		}
	}
}

func TestCallerStopDoesNotMarkRecovery(t *testing.T) {
	reg := NewRegistry(nil, nil)
	reg.Trip(1, "previous failure", false)
	p := New([]*Member{member(1, "a", 10, okProv("a", "partial"))}, reg)
	for range p.Stream(context.Background(), llm.CompletionRequest{}) {
		break
	}
	if reg.Get(1).Fails != 1 {
		t.Fatal("caller stopping stream cleared health")
	}
}

func TestCancellationDuringProviderDoesNotFailoverOrEraseHealth(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		a := &rawProvider{stream: func(context.Context) iter.Seq2[llm.StreamEvent, error] {
			return func(yield func(llm.StreamEvent, error) bool) {
				cancel()
				yield(llm.StreamEvent{}, errors.New("status 503: unavailable"))
			}
		}}
		b := okProv("backup", "must not run")
		reg := NewRegistry(nil, nil)
		reg.Trip(1, "previous failure", false)
		p := New([]*Member{member(1, "a", 10, a), member(2, "backup", 5, b)}, reg)
		var err error
		if streaming {
			_, err = drain(p.Stream(ctx, llm.CompletionRequest{}))
		} else {
			_, _, _, err = p.Complete(ctx, llm.CompletionRequest{})
		}
		if !errors.Is(err, context.Canceled) || b.calls != 0 || reg.Get(1).Fails != 1 {
			t.Fatalf("cancellation mishandled: %v calls=%d state=%+v", err, b.calls, reg.Get(1))
		}
	}
}
