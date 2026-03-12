package correlate

import "testing"

func TestCorrelate(t *testing.T) {
	tests := []struct {
		name     string
		fired    []string
		wantIDs  []string
		wantNone bool
	}{
		{
			"no fired rules → no correlations",
			nil,
			nil,
			true,
		},
		{
			"only one of two required rules → no correlation",
			[]string{"NV3302"},
			nil,
			true,
		},
		{
			"C001: NV3302 + NV5102",
			[]string{"NV3302", "NV5102"},
			[]string{"C001"},
			false,
		},
		{
			"C002: NV1001 + NV3302",
			[]string{"NV1001", "NV3302"},
			[]string{"C002"},
			false,
		},
		{
			"C003: NV3305 + NV5102",
			[]string{"NV3305", "NV5102"},
			[]string{"C003"},
			false,
		},
		{
			"C004: NV1002 + NV3301",
			[]string{"NV1002", "NV3301"},
			[]string{"C004"},
			false,
		},
		{
			"C005: NV3304 + NV5102",
			[]string{"NV3304", "NV5102"},
			[]string{"C005"},
			false,
		},
		{
			"multiple correlations from many fired rules",
			[]string{"NV1001", "NV1002", "NV3301", "NV3302", "NV3304", "NV3305", "NV5102"},
			[]string{"C001", "C002", "C003", "C004", "C005"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Correlate(tt.fired)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no correlations, got %d", len(got))
				}
				return
			}
			gotIDs := make(map[string]bool, len(got))
			for _, f := range got {
				gotIDs[f.ID] = true
			}
			for _, want := range tt.wantIDs {
				if !gotIDs[want] {
					t.Errorf("expected correlation %s, not found", want)
				}
			}
			if len(got) != len(tt.wantIDs) {
				t.Errorf("got %d correlations, want %d", len(got), len(tt.wantIDs))
			}
		})
	}
}
