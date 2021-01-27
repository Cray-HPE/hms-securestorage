// MIT License
//
// (C) Copyright [2019, 2021] Hewlett Packard Enterprise Development LP
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package securestorage

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"reflect"
	"testing"
)

type creds struct {
	Xname    string
	URL      string
	Username string
	Password string
}

func TestVaultAdapterStore(t *testing.T) {
	var tests = []struct {
		key      string
		value    interface{}
		vKeyPath []string
		vWData   []MockVWrite
		respErr  bool
	}{
		{
			key: "x0c0s1b0",
			value: creds{
				Xname:    "x0c0s1b0",
				URL:      "10.4.0.21/redfish/v1/UpdateService",
				Username: "test1",
				Password: "123",
			},
			vKeyPath: []string{"secret/hms-cred/x0c0s1b0"},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			respErr: false,
		}, {
			key: "x0c0s1b0",
			value: creds{
				Xname:    "x0c0s1b0",
				URL:      "10.4.0.21/redfish/v1/UpdateService",
				Username: "test1",
				Password: "123",
			},
			vKeyPath: []string{"secret/hms-cred/x0c0s1b0", "auth/kubernetes/login", "secret/hms-cred/x0c0s1b0"},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				}, {
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: nil,
					},
				}, {
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			respErr: false,
		}, {
			key: "x0c0s1b0",
			value: creds{
				Xname:    "x0c0s1b0",
				URL:      "10.4.0.21/redfish/v1/UpdateService",
				Username: "test1",
				Password: "123",
			},
			vKeyPath: []string{"secret/hms-cred/x0c0s1b0", "auth/kubernetes/login"},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				}, {
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: fmt.Errorf("Token Failed"),
					},
				},
			},
			respErr: true,
		},
	}

	ss := &VaultAdapter{
		BasePath:   "secret/hms-cred",
		VaultRetry: 1,
	}
	ss.AuthConfig = &AuthConfig{
		JWTFile:  "token",
		RoleFile: "namespace",
		Path:     "auth/kubernetes/login",
	}
	var vmock *MockVaultApi
	ss.Client, vmock = NewMockVaultApi()
	for i, test := range tests {
		vmock.WriteNum = 0
		vmock.WriteData = test.vWData
		err := ss.Store(test.key, test.value)
		if err == nil && !test.respErr {
			for j, data := range test.vWData {
				if data.Input.Path != test.vKeyPath[j] {
					t.Errorf("Test %v Failed: Expected path #%v %v but got %v", i, j, test.vKeyPath[j], data.Input.Path)
				}
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}

func TestVaultAdapterLookup(t *testing.T) {
	var secretData map[string]interface{}
	value := creds{
		Xname:    "x0c0s1b0",
		URL:      "10.4.0.21/redfish/v1/UpdateService",
		Username: "test1",
		Password: "123",
	}
	mapstructure.Decode(value, &secretData)
	var tests = []struct {
		key       string
		vRKeyPath []string
		vWKeyPath []string
		vRData    []MockVRead
		vWData    []MockVWrite
		resp      *creds
		respErr   bool
	}{
		{
			key:       "x0c0s1b0",
			vRKeyPath: []string{"secret/hms-cred/x0c0s1b0"},
			vWKeyPath: []string{},
			vRData: []MockVRead{
				{
					Output: OutputVRead{
						S:   &api.Secret{Data: secretData},
						Err: nil,
					},
				},
			},
			vWData:  []MockVWrite{},
			resp:    &value,
			respErr: false,
		}, {
			key:       "x0c0s1b0",
			vRKeyPath: []string{"secret/hms-cred/x0c0s1b0", "secret/hms-cred/x0c0s1b0"},
			vWKeyPath: []string{"auth/kubernetes/login"},
			vRData: []MockVRead{
				{
					Output: OutputVRead{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				}, {
					Output: OutputVRead{
						S:   &api.Secret{Data: secretData},
						Err: nil,
					},
				},
			},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			resp:    &value,
			respErr: false,
		}, {
			key:       "x0c0s1b0",
			vRKeyPath: []string{"secret/hms-cred/x0c0s1b0"},
			vWKeyPath: []string{"auth/kubernetes/login"},
			vRData: []MockVRead{
				{
					Output: OutputVRead{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				},
			},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: fmt.Errorf("Token Failed"),
					},
				},
			},
			resp:    &creds{},
			respErr: true,
		},
	}

	ss := &VaultAdapter{
		BasePath:   "secret/hms-cred",
		VaultRetry: 1,
	}
	ss.AuthConfig = &AuthConfig{
		JWTFile:  "token",
		RoleFile: "namespace",
		Path:     "auth/kubernetes/login",
	}
	var vmock *MockVaultApi
	ss.Client, vmock = NewMockVaultApi()
	for i, test := range tests {
		vmock.ReadNum = 0
		vmock.ReadData = test.vRData
		vmock.WriteNum = 0
		vmock.WriteData = test.vWData
		var r creds
		err := ss.Lookup(test.key, &r)
		if err == nil && !test.respErr {
			for j, data := range test.vRData {
				if data.Input.Path != test.vRKeyPath[j] {
					t.Errorf("Test %v Failed: Expected Read path #%v %v but got %v", i, j, test.vRKeyPath[j], data.Input.Path)
				}
			}
			for j, data := range test.vWData {
				if data.Input.Path != test.vWKeyPath[j] {
					t.Errorf("Test %v Failed: Expected Write path #%v %v but got %v", i, j, test.vWKeyPath[j], data.Input.Path)
				}
			}
			if !reflect.DeepEqual(r, *test.resp) {
				t.Errorf("Test %v Failed: Expected credentials %v but got %v", i, test.resp, r)
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}

func TestVaultAdapterDelete(t *testing.T) {
	var tests = []struct {
		key       string
		vDKeyPath []string
		vWKeyPath []string
		vDData    []MockVDelete
		vWData    []MockVWrite
		respErr   bool
	}{
		{
			key:       "x0c0s1b0",
			vDKeyPath: []string{"secret/hms-cred/x0c0s1b0"},
			vWKeyPath: []string{},
			vDData: []MockVDelete{
				{
					Output: OutputVDelete{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			vWData:  []MockVWrite{},
			respErr: false,
		}, {
			key:       "x0c0s1b0",
			vDKeyPath: []string{"secret/hms-cred/x0c0s1b0", "secret/hms-cred/x0c0s1b0"},
			vWKeyPath: []string{"auth/kubernetes/login"},
			vDData: []MockVDelete{
				{
					Output: OutputVDelete{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				}, {
					Output: OutputVDelete{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			respErr: false,
		}, {
			key:       "x0c0s1b0",
			vDKeyPath: []string{"secret/hms-cred/x0c0s1b0", "auth/kubernetes/login"},
			vWKeyPath: []string{"secret/hms-cred/x0c0s1b0", "auth/kubernetes/login"},
			vDData: []MockVDelete{
				{
					Output: OutputVDelete{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				},
			},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: fmt.Errorf("Token Failed"),
					},
				},
			},
			respErr: true,
		},
	}

	ss := &VaultAdapter{
		BasePath:   "secret/hms-cred",
		VaultRetry: 1,
	}
	ss.AuthConfig = &AuthConfig{
		JWTFile:  "token",
		RoleFile: "namespace",
		Path:     "auth/kubernetes/login",
	}
	var vmock *MockVaultApi
	ss.Client, vmock = NewMockVaultApi()
	for i, test := range tests {
		vmock.DeleteNum = 0
		vmock.DeleteData = test.vDData
		vmock.WriteNum = 0
		vmock.WriteData = test.vWData
		err := ss.Delete(test.key)
		if err == nil && !test.respErr {
			for j, data := range test.vDData {
				if data.Input.Path != test.vDKeyPath[j] {
					t.Errorf("Test %v Failed: Expected Delete path #%v %v but got %v", i, j, test.vDKeyPath[j], data.Input.Path)
				}
			}
			for j, data := range test.vWData {
				if data.Input.Path != test.vWKeyPath[j] {
					t.Errorf("Test %v Failed: Expected Write path #%v %v but got %v", i, j, test.vWKeyPath[j], data.Input.Path)
				}
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}

func TestVaultAdapterLookupKeys(t *testing.T) {
	values := []interface{}{"x0c0s1b0", "x0c0s2b0"}
	secretData := map[string]interface{}{
		"keys": values,
	}
	var tests = []struct {
		keyPath   string
		vLKeyPath []string
		vWKeyPath []string
		vLData    []MockVList
		vWData    []MockVWrite
		resp      []string
		respErr   bool
	}{
		{
			keyPath:   "",
			vLKeyPath: []string{"secret/hms-cred/"},
			vWKeyPath: []string{},
			vLData: []MockVList{
				{
					Output: OutputVList{
						S:   &api.Secret{Data: secretData},
						Err: nil,
					},
				},
			},
			vWData:  []MockVWrite{},
			resp:    []string{"x0c0s1b0", "x0c0s1b0"},
			respErr: false,
		}, {
			keyPath:   "",
			vLKeyPath: []string{"secret/hms-cred/", "secret/hms-cred/"},
			vWKeyPath: []string{"auth/kubernetes/login"},
			vLData: []MockVList{
				{
					Output: OutputVList{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				}, {
					Output: OutputVList{
						S:   &api.Secret{Data: secretData},
						Err: nil,
					},
				},
			},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: nil,
					},
				},
			},
			resp:    []string{"x0c0s1b0", "x0c0s1b0"},
			respErr: false,
		}, {
			keyPath:   "",
			vLKeyPath: []string{"secret/hms-cred/"},
			vWKeyPath: []string{"auth/kubernetes/login"},
			vLData: []MockVList{
				{
					Output: OutputVList{
						S:   &api.Secret{},
						Err: fmt.Errorf("Code: 403"),
					},
				},
			},
			vWData: []MockVWrite{
				{
					Output: OutputVWrite{
						S:   &api.Secret{},
						Err: fmt.Errorf("Token Failed"),
					},
				},
			},
			resp:    []string{},
			respErr: true,
		},
	}

	ss := &VaultAdapter{
		BasePath:   "secret/hms-cred",
		VaultRetry: 1,
	}
	ss.AuthConfig = &AuthConfig{
		JWTFile:  "token",
		RoleFile: "namespace",
		Path:     "auth/kubernetes/login",
	}
	var vmock *MockVaultApi
	ss.Client, vmock = NewMockVaultApi()
	for i, test := range tests {
		vmock.ListNum = 0
		vmock.ListData = test.vLData
		vmock.WriteNum = 0
		vmock.WriteData = test.vWData
		r, err := ss.LookupKeys(test.keyPath)
		if err == nil && !test.respErr {
			for j, data := range test.vLData {
				if data.Input.Path != test.vLKeyPath[j] {
					t.Errorf("Test %v Failed: Expected List path #%v %v but got %v", i, j, test.vLKeyPath[j], data.Input.Path)
				}
			}
			for j, data := range test.vWData {
				if data.Input.Path != test.vWKeyPath[j] {
					t.Errorf("Test %v Failed: Expected Write path #%v %v but got %v", i, j, test.vWKeyPath[j], data.Input.Path)
				}
			}
			var found bool
			for _, key := range test.resp {
				found = false
				for _, rkey := range r {
					if key == rkey {
						found = true
						break
					}
				}
				if !found {
					break
				}
			}
			if !found {
				t.Errorf("Test %v Failed: Expected keys %v but got %v", i, test.resp, r)
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}
