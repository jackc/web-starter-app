package formerrors

type Error struct {
	Field string
	Error string
}

type Errors struct {
	errors []Error
}

func (e *Errors) Add(field string, err string) {
	e.errors = append(e.errors, Error{Field: field, Error: err})
}

func (e *Errors) Len() int {
	if e == nil {
		return 0
	}

	return len(e.errors)
}

func (e *Errors) Any() bool {
	if e == nil {
		return false
	}

	return len(e.errors) > 0
}

func (e *Errors) All() []Error {
	if e == nil {
		return nil
	}

	return e.errors
}

func (e *Errors) Has(field string) bool {
	if e == nil {
		return false
	}

	for _, err := range e.errors {
		if err.Field == field {
			return true
		}
	}
	return false
}

func (e *Errors) For(field string) []string {
	if e == nil {
		return nil
	}

	var errs []string
	for _, err := range e.errors {
		if err.Field == field {
			errs = append(errs, err.Error)
		}
	}
	return errs
}
