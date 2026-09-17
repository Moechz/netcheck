package collector

import "testing"

func TestRate(t *testing.T) {
	tests := []struct {
		name     string
		current  uint64
		previous uint64
		seconds  float64
		want     float64
	}{
		{"one_byte_one_second", 2, 1, 1, 8},
		{"zero_interval", 2, 1, 0, 0},
		{"counter_rollback", 1, 2, 1, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rate(test.current, test.previous, test.seconds); got != test.want {
				t.Fatalf("rate() = %v, want %v", got, test.want)
			}
		})
	}
}
