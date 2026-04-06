package detector

// PIIType identifies the category of a detected PII entity.
type PIIType string

const (
	PIITypeCreditCard   PIIType = "CREDIT_CARD"
	PIITypePhoneNumber  PIIType = "PHONE_NUMBER"
	PIITypeEmail        PIIType = "EMAIL"
	PIITypePersonName   PIIType = "PERSON_NAME"
	PIITypeHomeAddress  PIIType = "HOME_ADDRESS"
	PIITypeNationalID   PIIType = "NATIONAL_ID"
	PIITypeBankAccount  PIIType = "BANK_ACCOUNT"
	PIITypeIPAddress    PIIType = "IP_ADDRESS"
	PIITypeDateOfBirth  PIIType = "DATE_OF_BIRTH"
	PIITypePassport     PIIType = "PASSPORT"
)

// AllPIITypes lists all supported PII types in detection order.
var AllPIITypes = []PIIType{
	PIITypeCreditCard,
	PIITypePhoneNumber,
	PIITypeEmail,
	PIITypePersonName,
	PIITypeHomeAddress,
	PIITypeNationalID,
	PIITypeBankAccount,
	PIITypeIPAddress,
	PIITypeDateOfBirth,
	PIITypePassport,
}

// regexDetectedTypes are handled locally by regex; no LLM call needed.
var regexDetectedTypes = map[PIIType]bool{
	PIITypeCreditCard:  true,
	PIITypePhoneNumber: true,
	PIITypeEmail:       true,
	PIITypeIPAddress:   true,
	PIITypeBankAccount: true,
}

// PIIEntity is one detected PII span inside the input text.
type PIIEntity struct {
	Type       PIIType
	Value      string  // exact substring as it appears in the text
	Start      int     // byte offset in original text
	End        int
	Confidence float64 // 0.0–1.0
}

// DetectionResult holds all entities found in one input text.
type DetectionResult struct {
	Entities []PIIEntity
	Text     string // original input (kept for offset validation)
}
