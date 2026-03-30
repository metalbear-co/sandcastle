{{/*
Expand the name of the chart.
*/}}
{{- define "sandcastle.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
If release name already contains "sandcastle", use it as-is.
Otherwise, append "-sandcastle".
*/}}
{{- define "sandcastle.fullname" -}}
{{- if contains "sandcastle" .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-sandcastle" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sandcastle.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "sandcastle.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sandcastle.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sandcastle.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Build DATABASE_URL.
If storage.databaseUrl is set, use it directly.
If postgresql.enabled, build the URL from the in-chart postgres service.
*/}}
{{- define "sandcastle.databaseUrl" -}}
{{- if .Values.storage.databaseUrl }}
{{- .Values.storage.databaseUrl }}
{{- else if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgres/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "sandcastle.fullname" .) .Values.postgresql.auth.database }}
{{- end }}
{{- end }}

{{/*
Whether postgres storage should be used.
*/}}
{{- define "sandcastle.usePostgres" -}}
{{- if or .Values.postgresql.enabled .Values.storage.databaseUrl }}
{{- "true" }}
{{- end }}
{{- end }}
