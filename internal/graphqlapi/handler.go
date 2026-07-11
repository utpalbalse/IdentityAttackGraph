package graphqlapi

import (
	"encoding/json"
	"net/http"

	"github.com/graphql-go/graphql"
)

// Handler serves GraphQL over HTTP: POST a JSON body {query, variables, operationName}, or GET with
// a ?query= param. Errors are returned in the standard GraphQL response shape (200 with an "errors"
// array), so clients get partial data + errors rather than an opaque HTTP failure.
func Handler(schema graphql.Schema, ds DataSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var query, op string
		var vars map[string]any

		switch r.Method {
		case http.MethodGet:
			query = r.URL.Query().Get("query")
		case http.MethodPost:
			var body struct {
				Query         string         `json:"query"`
				Variables     map[string]any `json:"variables"`
				OperationName string         `json:"operationName"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			query, vars, op = body.Query, body.Variables, body.OperationName
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if query == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  query,
			VariableValues: vars,
			OperationName:  op,
			Context:        withGraphCache(r.Context(), ds),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}
