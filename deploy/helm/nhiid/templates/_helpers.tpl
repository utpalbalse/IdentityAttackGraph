{{/* Expand the name of the chart. */}}
{{- define "nhiid.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "nhiid.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nhiid.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "nhiid.labels" -}}
helm.sh/chart: {{ include "nhiid.chart" . }}
{{ include "nhiid.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nhiid
{{- end -}}

{{/* Selector labels (stable across upgrades). */}}
{{- define "nhiid.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nhiid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "nhiid.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "nhiid.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "nhiid.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "nhiid.web.image" -}}
{{- $tag := default .Chart.AppVersion .Values.web.image.tag -}}
{{- printf "%s:%s" .Values.web.image.repository $tag -}}
{{- end -}}

{{- define "nhiid.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "nhiid.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Assemble the Postgres DSN. Precedence: explicit secrets.databaseDSN / externalDatabase.dsn,
then the in-cluster postgresql subchart, then the externalDatabase parts.
*/}}
{{- define "nhiid.databaseDSN" -}}
{{- if .Values.secrets.databaseDSN -}}
{{- .Values.secrets.databaseDSN -}}
{{- else if .Values.externalDatabase.dsn -}}
{{- .Values.externalDatabase.dsn -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "postgres://%s:%s@%s-postgresql:5432/%s?sslmode=disable" .Values.postgresql.auth.username .Values.postgresql.auth.password .Release.Name .Values.postgresql.auth.database -}}
{{- else -}}
{{- printf "postgres://%s:%s@%s:%v/%s?sslmode=%s" .Values.externalDatabase.user .Values.externalDatabase.password .Values.externalDatabase.host (.Values.externalDatabase.port | int) .Values.externalDatabase.database .Values.externalDatabase.sslmode -}}
{{- end -}}
{{- end -}}

{{- define "nhiid.redisURL" -}}
{{- if .Values.externalRedis.url -}}
{{- .Values.externalRedis.url -}}
{{- else if .Values.redis.enabled -}}
{{- printf "redis://%s-redis-master:6379/0" .Release.Name -}}
{{- end -}}
{{- end -}}

{{- define "nhiid.natsURL" -}}
{{- if .Values.externalNats.url -}}
{{- .Values.externalNats.url -}}
{{- else if .Values.nats.enabled -}}
{{- printf "nats://%s-nats:4222" .Release.Name -}}
{{- end -}}
{{- end -}}

{{/*
Shared env for api/worker/migrate: the DB DSN (and JWT secret in jwt mode) sourced from the Secret.
The rest of configuration comes from the mounted config.yaml.
*/}}
{{- define "nhiid.backendEnv" -}}
- name: NHIID_DATABASE_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "nhiid.secretName" . }}
      key: database-dsn
{{- if eq .Values.config.auth.mode "jwt" }}
- name: NHIID_AUTH_JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "nhiid.secretName" . }}
      key: jwt-secret
      optional: true
{{- end }}
{{- if .Values.config.notify.enabled }}
- name: NHIID_NOTIFY_WEBHOOK_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "nhiid.secretName" . }}
      key: notify-webhook-url
      optional: true
{{- end }}
{{- end -}}

{{/* Volume + mount that overrides /app/configs/config.yaml (and tokens.json in token mode). */}}
{{- define "nhiid.configVolume" -}}
- name: config
  configMap:
    name: {{ include "nhiid.fullname" . }}-config
{{- if eq .Values.config.auth.mode "token" }}
- name: auth-tokens
  secret:
    secretName: {{ include "nhiid.secretName" . }}
    items:
      - key: auth-tokens
        path: tokens.json
{{- end }}
- name: tmp
  emptyDir: {}
{{- end -}}

{{- define "nhiid.configMounts" -}}
- name: config
  mountPath: /app/configs/config.yaml
  subPath: config.yaml
  readOnly: true
{{- if eq .Values.config.auth.mode "token" }}
- name: auth-tokens
  mountPath: /app/secrets
  readOnly: true
{{- end }}
- name: tmp
  mountPath: /tmp
{{- end -}}
