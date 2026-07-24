package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

func FinalizePlan(payload PlanPayload) (Plan, error) {
	encoded, err := json.Marshal(payload)
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
	if err := json.Unmarshal(content, &plan); err != nil {
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
