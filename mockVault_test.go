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
)

type InputVRead struct {
	Path string
}

type OutputVRead struct {
	S   *api.Secret
	Err error
}

type MockVRead struct {
	Input  InputVRead
	Output OutputVRead
}

type InputVWrite struct {
	Path string
	Data map[string]interface{}
}

type OutputVWrite struct {
	S   *api.Secret
	Err error
}

type MockVWrite struct {
	Input  InputVWrite
	Output OutputVWrite
}

type InputVDelete struct {
	Path string
}

type OutputVDelete struct {
	S   *api.Secret
	Err error
}

type MockVDelete struct {
	Input  InputVDelete
	Output OutputVDelete
}

type InputVList struct {
	Path string
}

type OutputVList struct {
	S   *api.Secret
	Err error
}

type MockVList struct {
	Input  InputVList
	Output OutputVList
}

type MockVaultApi struct {
	ReadNum    int
	ReadData   []MockVRead
	WriteNum   int
	WriteData  []MockVWrite
	DeleteNum  int
	DeleteData []MockVDelete
	ListNum    int
	ListData   []MockVList
}

func NewMockVaultApi() (VaultApi, *MockVaultApi) {
	v := &MockVaultApi{}
	return v, v
}

func (v *MockVaultApi) Read(path string) (*api.Secret, error) {
	i := v.ReadNum
	if len(v.ReadData) <= i {
		return nil, fmt.Errorf("Unexpected call to MockVRead")
	}
	v.ReadNum++
	v.ReadData[i].Input.Path = path
	return v.ReadData[i].Output.S, v.ReadData[i].Output.Err
}

func (v *MockVaultApi) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	i := v.WriteNum
	if len(v.WriteData) <= i {
		return nil, fmt.Errorf("Unexpected call to MockVWrite")
	}
	v.WriteNum++
	v.WriteData[i].Input.Path = path
	v.WriteData[i].Input.Data = data
	return v.WriteData[i].Output.S, v.WriteData[i].Output.Err
}

func (v *MockVaultApi) Delete(path string) (*api.Secret, error) {
	i := v.DeleteNum
	if len(v.DeleteData) <= i {
		return nil, fmt.Errorf("Unexpected call to MockVDelete")
	}
	v.DeleteNum++
	v.DeleteData[i].Input.Path = path
	return v.DeleteData[i].Output.S, v.DeleteData[i].Output.Err
}

func (v *MockVaultApi) List(path string) (*api.Secret, error) {
	i := v.ListNum
	if len(v.ListData) <= i {
		return nil, fmt.Errorf("Unexpected call to MockVList")
	}
	v.ListNum++
	v.ListData[i].Input.Path = path
	return v.ListData[i].Output.S, v.ListData[i].Output.Err
}

func (v *MockVaultApi) SetToken(t string) {
	return
}
