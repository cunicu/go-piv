// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcsc

import "fmt"

type scErr struct {
	// rc holds the return code for a given call.
	rc int64
}

func (e *scErr) Error() string {
	if msg, ok := pcscErrMsgs[e.rc]; ok {
		return msg
	}
	return fmt.Sprintf("unknown pcsc return code 0x%08x", e.rc)
}
