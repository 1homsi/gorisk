package capabilities

import (
	"testing"
)

func TestMeetsMinRisk(t *testing.T) {
	tests := []struct {
		name  string
		level string
		min   string
		want  bool
	}{
		{
			name:  "HIGH meets HIGH",
			level: "HIGH",
			min:   "HIGH",
			want:  true,
		},
		{
			name:  "HIGH meets MEDIUM",
			level: "HIGH",
			min:   "MEDIUM",
			want:  true,
		},
		{
			name:  "HIGH meets LOW",
			level: "HIGH",
			min:   "LOW",
			want:  true,
		},
		{
			name:  "MEDIUM does not meet HIGH",
			level: "MEDIUM",
			min:   "HIGH",
			want:  false,
		},
		{
			name:  "MEDIUM meets MEDIUM",
			level: "MEDIUM",
			min:   "MEDIUM",
			want:  true,
		},
		{
			name:  "MEDIUM meets LOW",
			level: "MEDIUM",
			min:   "LOW",
			want:  true,
		},
		{
			name:  "LOW does not meet HIGH",
			level: "LOW",
			min:   "HIGH",
			want:  false,
		},
		{
			name:  "LOW does not meet MEDIUM",
			level: "LOW",
			min:   "MEDIUM",
			want:  false,
		},
		{
			name:  "LOW meets LOW",
			level: "LOW",
			min:   "LOW",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := meetsMinRisk(tt.level, tt.min)
			if got != tt.want {
				t.Errorf("meetsMinRisk(%q, %q) = %v, want %v", tt.level, tt.min, got, tt.want)
			}
		})
	}
}
