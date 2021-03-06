package authutils_test

import (
	"crypto/rsa"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/auth-library/internal/testutils"
)

func TestGetKeyFingerprint(t *testing.T) {
	key := testutils.GetSamplePubKey()

	type args struct {
		key *rsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"returns fingerprint for valid key", args{key.Key}, testutils.GetSamplePubKeyFingerprint(), false},
		{"errors on nil key", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authutils.GetKeyFingerprint(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetKeyFingerprint() = %v, error = %v, wantErr %v", got, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetKeyFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashSha256(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantHex string
		wantErr bool
	}{
		{"found", args{[]byte("This is a test.")}, "a8a2f6ebe286697c527eb35a58b5539532e9b3ae3b64d4eb0a46fb657b41562c", false},
		{"empty", args{[]byte{}}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"nil", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authutils.HashSha256(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashSha256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var want []byte
			if tt.wantHex != "" {
				want, err = hex.DecodeString(tt.wantHex)
				if err != nil {
					t.Errorf("error decoding test want hex: %s", tt.wantHex)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("HashSha256() = %v, want %v", got, want)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	type args struct {
		slice []string
		val   string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"return true when found", args{[]string{"test1", "test2", "test3"}, "test2"}, true},
		{"return false when not found", args{[]string{"test1", "test2", "test3"}, "test5"}, false},
		{"return false on partial match", args{[]string{"test1", "test2", "test3"}, "test"}, false},
		{"return false on nil slice", args{nil, "test"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authutils.ContainsString(tt.args.slice, tt.args.val); got != tt.want {
				t.Errorf("ContainsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoveString(t *testing.T) {
	type args struct {
		slice []string
		val   string
	}
	tests := []struct {
		name  string
		args  args
		want  []string
		want1 bool
	}{
		{"return modified list, true when found", args{[]string{"test1", "test2", "test3"}, "test2"}, []string{"test1", "test3"}, true},
		{"return unmodified list, false when not found", args{[]string{"test1", "test2", "test3"}, "test5"}, []string{"test1", "test2", "test3"}, false},
		{"return unmodified list, false on partial match", args{[]string{"test1", "test2", "test3"}, "test"}, []string{"test1", "test2", "test3"}, false},
		{"return nil, false on nil slice", args{nil, "test"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := authutils.RemoveString(tt.args.slice, tt.args.val)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveString() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("RemoveString() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGetPubKeyPem(t *testing.T) {
	sampleKey := testutils.GetSamplePubKey().Key
	sampleKeyPem := testutils.GetSamplePubKeyPem() + "\n"

	type args struct {
		key *rsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"return error on nil key", args{sampleKey}, sampleKeyPem, false},
		{"return error on nil key", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authutils.GetPubKeyPem(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPubKeyPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetPubKeyPem() = %v, want %v", got, tt.want)
			}
		})
	}
}
