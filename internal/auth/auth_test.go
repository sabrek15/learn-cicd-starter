package auth

import (
	"errors"
	"net/http"
	"testing"
)


func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name		string
		header		http.Header
		expectedKey	string
		expectedErr	error
	} {
		{
			name: "vaild_header",
			header:	http.Header{"Authorization": []string{"Apikey my-secret-api-key"}},
			expectedKey: "my-secret-api-key",
			expectedErr: nil,
		},

		{
			name: "missing_header",
			header: http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},

		{
			name: "malformed_header_no_key",
			header: http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},

		{
			name: "malformed_header_wrong_scheme",
			header: http.Header{"Authorization": []string{"Bearer my-secret-api-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},

	}

	for _, tc := range testCases {
		t.Run(tc.name, func (t *testing.T) {
			apikey, err := GetAPIKey(tc.header)
			
			if apikey != tc.expectedKey {
				t.Errorf("expected key '%s', but got '%s'", tc.expectedKey, apikey)
			}
			
			if tc.expectedErr == nil && err != nil {
				t.Errorf("expected no error, but got '%v'", err)
			}

			if tc.expectedErr != nil && err == nil {
				t.Errorf("expected error is '%v', but got nil", tc.expectedErr)
			}

			if tc.expectedErr != nil && err != nil && tc.expectedErr.Error() != err.Error() {
				t.Errorf("expected error '%v', but got '%v'", tc.expectedErr, err)
			}
		})
	}
}