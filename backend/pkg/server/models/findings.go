package models

import (
	"encoding/json"
	"time"
)

// Finding is a security finding recorded by an agent and reviewed by a person.
// nolint:lll
type Finding struct {
	ID          uint64     `form:"id" json:"id" validate:"min=0,numeric" gorm:"type:BIGINT;NOT NULL;PRIMARY_KEY;AUTO_INCREMENT"`
	FlowID      uint64     `form:"flow_id" json:"flow_id" validate:"min=0,numeric,required" gorm:"type:BIGINT;NOT NULL"`
	TaskID      *uint64    `form:"task_id,omitempty" json:"task_id,omitempty" validate:"omitnil,min=0" gorm:"type:BIGINT"`
	SubtaskID   *uint64    `form:"subtask_id,omitempty" json:"subtask_id,omitempty" validate:"omitnil,min=0" gorm:"type:BIGINT"`
	Title       string     `json:"title" validate:"required" gorm:"type:TEXT;NOT NULL"`
	Severity    string     `json:"severity" validate:"required" gorm:"type:FINDING_SEVERITY;NOT NULL"`
	Status      string     `json:"status" validate:"required" gorm:"type:FINDING_STATUS;NOT NULL;default:'potential'"`
	CVSSVector  string     `json:"cvss_vector" gorm:"column:cvss_vector;type:TEXT;NOT NULL;default:''"`
	CVSSScore   float64    `json:"cvss_score" gorm:"column:cvss_score;type:NUMERIC(3,1);NOT NULL;default:0"`
	Asset       string     `json:"asset" validate:"required" gorm:"type:TEXT;NOT NULL"`
	Description string     `json:"description" gorm:"type:TEXT;NOT NULL"`
	Impact      string     `json:"impact" gorm:"type:TEXT;NOT NULL;default:''"`
	Evidence    string     `json:"evidence" gorm:"type:TEXT;NOT NULL;default:''"`
	Remediation string     `json:"remediation" gorm:"type:TEXT;NOT NULL"`
	Refs        string     `json:"-" gorm:"column:refs;type:JSON;NOT NULL;default:'[]'"`
	References  []string   `json:"references" gorm:"-"`
	ReviewedAt  *time.Time `form:"reviewed_at,omitempty" json:"reviewed_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ"`
	CreatedAt   time.Time  `form:"created_at,omitempty" json:"created_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time  `form:"updated_at,omitempty" json:"updated_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ;default:CURRENT_TIMESTAMP"`
}

// TableName returns the table name string to guaranty use correct table
func (f *Finding) TableName() string {
	return "findings"
}

// DecodeRefs fills References from the stored JSON column. A malformed column
// yields an empty list rather than failing the whole request.
func (f *Finding) DecodeRefs() {
	f.References = []string{}
	if f.Refs == "" {
		return
	}
	var refs []string
	if err := json.Unmarshal([]byte(f.Refs), &refs); err == nil && refs != nil {
		f.References = refs
	}
}
