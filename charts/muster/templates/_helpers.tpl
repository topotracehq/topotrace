{{/*
Base name for the chart (not the release) -- "muster".
*/}}
{{- define "muster.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{/*
Release-qualified name, e.g. "myrelease-muster". Used as the prefix for
every object this chart creates so multiple releases in one namespace
don't collide.
*/}}
{{- define "muster.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "muster.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard recommended labels, per the Kubernetes docs' common-label
convention (app.kubernetes.io/*).
*/}}
{{- define "muster.labels" -}}
app.kubernetes.io/name: {{ include "muster.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/*
Selector labels -- the subset of muster.labels that's safe to use in a
selector (no chart-version/managed-by churn breaking selector immutability
across upgrades).
*/}}
{{- define "muster.selectorLabels" -}}
app.kubernetes.io/name: {{ include "muster.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Name of the Secret holding the Postgres DSN -- either the chart-managed
one, or the user's own existingSecret override.
*/}}
{{- define "muster.postgresSecretName" -}}
{{- if .Values.postgres.credentials.existingSecret -}}
{{- .Values.postgres.credentials.existingSecret -}}
{{- else -}}
{{- printf "%s-postgres" (include "muster.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Full Postgres DSN, built from the chart-managed credentials. Only
meaningful when existingSecret is unset -- the chart-generated Secret is
the one place this actually gets rendered.
*/}}
{{- define "muster.postgresDSN" -}}
{{- printf "postgres://%s:%s@%s-postgres:5432/%s?sslmode=disable" .Values.postgres.credentials.user .Values.postgres.credentials.password (include "muster.fullname" .) .Values.postgres.credentials.database -}}
{{- end -}}

{{/*
Whether any auth-token source is configured at all (a plaintext
auth.token value or an auth.existingSecret) -- deployment-muster.yaml
and the agent templates use this to decide whether to wire
MUSTER_AUTH_TOKEN/--token in at all. Empty string (falsy in Helm's `if`)
when neither is set.
*/}}
{{- define "muster.authEnabled" -}}
{{- if or .Values.auth.token .Values.auth.existingSecret -}}true{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding the muster auth token -- either the
chart-managed one (rendered by secret-auth.yaml only when auth.token is
set), or the user's own existingSecret override. Only meaningful when
muster.authEnabled is "true" -- same guard pattern as
muster.postgresSecretName.
*/}}
{{- define "muster.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "muster.fullname" .) -}}
{{- end -}}
{{- end -}}
