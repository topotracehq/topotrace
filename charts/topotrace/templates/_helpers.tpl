{{/*
Base name for the chart (not the release) -- "topotrace".
*/}}
{{- define "topotrace.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{/*
Release-qualified name, e.g. "myrelease-topotrace". Used as the prefix for
every object this chart creates so multiple releases in one namespace
don't collide.
*/}}
{{- define "topotrace.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "topotrace.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard recommended labels, per the Kubernetes docs' common-label
convention (app.kubernetes.io/*).
*/}}
{{- define "topotrace.labels" -}}
app.kubernetes.io/name: {{ include "topotrace.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/*
Selector labels -- the subset of topotrace.labels that's safe to use in a
selector (no chart-version/managed-by churn breaking selector immutability
across upgrades).
*/}}
{{- define "topotrace.selectorLabels" -}}
app.kubernetes.io/name: {{ include "topotrace.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Name of the Secret holding the Postgres DSN -- either the chart-managed
one, or the user's own existingSecret override.
*/}}
{{- define "topotrace.postgresSecretName" -}}
{{- if .Values.postgres.credentials.existingSecret -}}
{{- .Values.postgres.credentials.existingSecret -}}
{{- else -}}
{{- printf "%s-postgres" (include "topotrace.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Full Postgres DSN, built from the chart-managed credentials. Only
meaningful when existingSecret is unset -- the chart-generated Secret is
the one place this actually gets rendered.
*/}}
{{- define "topotrace.postgresDSN" -}}
{{- printf "postgres://%s:%s@%s-postgres:5432/%s?sslmode=disable" .Values.postgres.credentials.user .Values.postgres.credentials.password (include "topotrace.fullname" .) .Values.postgres.credentials.database -}}
{{- end -}}

{{/*
Whether any auth-token source is configured at all (a plaintext
auth.token value or an auth.existingSecret) -- deployment-topotrace.yaml
and the agent templates use this to decide whether to wire
TOPOTRACE_AUTH_TOKEN/--token in at all. Empty string (falsy in Helm's `if`)
when neither is set.
*/}}
{{- define "topotrace.authEnabled" -}}
{{- if or .Values.auth.token .Values.auth.existingSecret -}}true{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding the topotrace auth token -- either the
chart-managed one (rendered by secret-auth.yaml only when auth.token is
set), or the user's own existingSecret override. Only meaningful when
topotrace.authEnabled is "true" -- same guard pattern as
topotrace.postgresSecretName.
*/}}
{{- define "topotrace.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "topotrace.fullname" .) -}}
{{- end -}}
{{- end -}}
