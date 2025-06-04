package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   bool
		errorText string // optional: zum Vergleich der Fehlermeldung
	}{
		{
			name:    "valid header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: false,
		},
		{
			name:      "missing header",
			headers:   http.Header{},
			wantKey:   "",
			wantErr:   true,
			errorText: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:      "malformed header prefix",
			headers:   http.Header{"Authorization": []string{"Bearer token"}},
			wantKey:   "",
			wantErr:   true,
			errorText: "malformed authorization header",
		},
		{
			name:      "missing token after prefix",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:   "",
			wantErr:   true,
			errorText: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errorText != "" && err.Error() != tt.errorText {
				t.Errorf("GetAPIKey() error = %v, wantErrorText %v", err.Error(), tt.errorText)
			}

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}
