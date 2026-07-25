package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/shellcell/snailmail/internal/jsonstrict"
)

func FinalizePlan(payload PlanPayload) (Plan, error) {
	encoded, err := canonicalJSON(payload)
	if err != nil {
		return Plan{}, err
	}
	digest := sha256.Sum256(encoded)
	return Plan{SchemaVersion: PlanSchema, PlanID: hex.EncodeToString(digest[:]), Payload: payload}, nil
}

func WritePlan(name string, plan Plan) error {
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return atomicWrite(name, encoded, 0o644)
}

func LoadPlan(name string) (Plan, error) {
	content, err := os.ReadFile(name)
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if err := jsonstrict.Decode(content, &plan, 16<<20); err != nil {
		return Plan{}, err
	}
	if plan.SchemaVersion != PlanSchema {
		return Plan{}, errors.New("unsupported plan schema")
	}
	expected, err := FinalizePlan(plan.Payload)
	if err != nil {
		return Plan{}, err
	}
	if expected.PlanID != plan.PlanID {
		return Plan{}, fmt.Errorf("plan ID does not match its payload")
	}
	return plan, nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := writeCanonicalJSON(&output, generic); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case json.Number:
		output.WriteString(typed.String())
	case string:
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(typed); err != nil {
			return err
		}
		output.WriteString(strings.TrimSuffix(encoded.String(), "\n"))
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSON(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeCanonicalJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}
