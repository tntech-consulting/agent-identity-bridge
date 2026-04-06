# AIB — Documentation des modifications — 6 avril 2026

## Vue d'ensemble

Journée de travail majeure couvrant : moteur de policies déclaratif, gouvernance Scale/Enterprise, page use cases interactive, DPA RGPD, mise à jour CGV.

---

## 1. Moteur de policies déclaratif générique

### Problème résolu
Avant cette session, chaque `rule_type` custom nécessitait un handler codé dans `passport-create`. Tout nouveau type nécessitait une modification et un redéploiement — bloquant l'admin.

### Architecture mise en place

**`passport-create` v20** — Le moteur évalue maintenant les conditions directement depuis le JSON stocké en base, sans aucune connaissance du `proposed_rule_type`.

Structure d'une custom policy :
```json
{
  "conditions": [
    { "field": "capabilities", "operator": "intersects_all_of",
      "value": [["mar_screening", "suspicious_pattern_detect"],
                ["regulatory_report_generate", "report_submit_esma"]] }
  ],
  "thresholds": { "count_what": "receipts", "max": 3 },
  "lookback_minutes": 10,
  "action_on_trigger": "block"
}
```

**Champs supportés :** `capabilities`, `protocols`, `tier`, `action`, `current_utc_hour`, `passport_id`

**Opérateurs supportés :** `intersects`, `intersects_all_of`, `contains`, `equals`, `not_equals`, `not_in`, `exists`, `gte`, `lte`

**Note critique :** `intersects_all_of` utilise `.every()` — TOUS les groupes doivent matcher. Corriger `.some()` → `.every()` si jamais ce bug réapparaît.

---

## 2. Gouvernance policies — Scale et Enterprise uniquement

### Décision produit
Les custom policies sont réservées aux plans Scale et Enterprise. Arguments : complexité de support, risque réputationnel sans battle-test, surface d'attaque.

### Implémentation DB (`policy_governance_scale_enterprise`)

**Table `policy_active_limits`** :
| Plan | Max actives | Max total |
|------|-------------|-----------|
| community | 0 | 0 |
| pro | 0 | 0 |
| scale | 10 | 30 |
| enterprise | 50 | 200 |

**Colonnes ajoutées à `custom_policy_rules`** :
- `plan_required` — `scale` ou `enterprise`
- `sanity_status` — `ok`, `warning`, `empty_rule`
- `sanity_warnings` — JSONB
- `evaluator_type` — `declarative` ou `legacy_hardcoded`
- `conditions`, `thresholds`, `lookback_minutes`

**Trigger `check_policy_plan_requirement()`** — bloque activation si :
- `validation_status != 'valid'`
- `sanity_status = 'empty_rule'`
- Plan insuffisant (`pro` ou `community`)
- Quota d'actives atteint

---

## 3. `policy-suggest` v7

### Nouveautés
- **Max 5 suggestions** (au lieu de 3)
- **Sanity checker intégré** à chaque sauvegarde — vérifie : empty_rule, always-true, tier invalide, seuil absurde, nom placeholder
- **Pool global `policy_templates`** — matching de pertinence par capabilities de l'org (seuil 20%)
- **Format déclaratif** — Claude génère des `conditions[]` et `thresholds` directement évaluables
- **Gouvernance renvoyée** dans la réponse : `plan_required`, `dryrun_endpoint`
- **Validateur déclaratif** — pas de whitelist, validation structurelle uniquement

### Sanity checker — cas détectés
| Cas | Status |
|-----|--------|
| Aucune condition + aucun threshold | `empty_rule` (non activable) |
| `current_utc_hour not_in []` | `warning` (always-true) |
| Tous les 24h exclus | `warning` (never-true) |
| `tier equals "superadmin"` | `warning` (tier invalide) |
| `threshold.max > 10000` | `warning` (absurde) |
| Nom placeholder (`test`, `my_rule`) | `warning` |
| Config correcte | `ok` |

---

## 4. `policy-dryrun` v2

### Endpoint
`GET/POST /policy-dryrun` (auth requise)

### Modes

**GET `?action=sanity&rule_id=...`** — sanity check d'une rule existante, met à jour `sanity_status` en DB.

**POST** avec `test_context` — 3 sous-modes :
1. `inline_rule` — tester une rule AVANT de la sauvegarder
2. `rule_id` — tester une rule spécifique
3. Sans l'un ni l'autre — tester toutes les rules `valid`/`activated` de l'org

**Paramètre spécial :** `simulated_utc_hour` (0-23) pour simuler une heure différente.

### Exemple de requête
```bash
curl -X POST https://vempwtzknixfnvysmiwo.supabase.co/functions/v1/policy-dryrun \
  -H "x-api-key: aib_sk_live_..." \
  -d '{
    "test_context": {
      "capabilities": ["mar_screening", "report_submit_esma"],
      "tier": "permanent",
      "simulated_utc_hour": 3
    }
  }'
```

### Réponse
```json
{
  "final_decision": "block",
  "explanation": "Request would be BLOCKED by 1 rule(s): settlement_market_hours_only",
  "rules_evaluated": 28,
  "rules_triggered": 1,
  "disclaimer": "Threshold counts not executed in dry-run..."
}
```

### Logs d'audit
Chaque dry-run est enregistré dans `policy_dryrun_logs` (org_id, test_context, résultats, décision finale).

---

## 5. Démo BNPSS Securities Services

4 agents créés avec contexts EU AI Act complets, 4 policies BNPSS activées :

| Policy | Règlement | Comportement |
|--------|-----------|-------------|
| `settlement_market_hours_only` | T2S + MAR | BLOCK hors 7h-17h UTC |
| `mar_screening_report_separation` | MAR Art.16 | BLOCK si agent cumule détection + reporting |
| `settlement_volume_control` | Bâle III | BLOCK si >3 settlements / 10 min |
| `esma_submission_permanent_only` | EMIR + SFTR | BLOCK si tier != permanent |

---

## 6. Page `/usecases` — Use Cases Interactifs

**URL DEV :** https://aib-dev.netlify.app/usecases  
**URL PROD :** https://aib-tech.fr/usecases

### Design
IBM Plex Mono + Syne, terminal de contrôle sécurisé, 4 onglets sectoriels.

### 4 use cases

**Berkmont Capital Group** (Finance, €240B AUM)
- Contraintes : T2S market hours, MAR SoD, Bâle III volume, ESMA permanent-only
- Terminal animé avec logs en temps réel, BLOCK/PASS visuels

**Rydell Health Systems** (47 cliniques DE/NL)
- Contraintes : PHI cross-patient isolation, diagnostic+prescription SoD, contact nocturne, consentement GDPR

**Nexara Networks** (18M abonnés Europe)
- Contraintes : throttle outreach 50/h, isolation réseau/facturation, plafond litiges €500, transparence Art.13 EU AI Act

**Orbital Aerostructures** (MRO, Toulouse)
- Contraintes : signature airworthiness humaine obligatoire, ITAR attestation, freeze window maintenance, STANAG chain

### Fonctionnalités
- Replay manuel par secteur
- Logs ligne par ligne avec timing réaliste
- Compteurs animés à l'entrée dans le viewport
- Auto-run au changement d'onglet

---

## 7. DPA — Accord de Traitement des Données

**Fichier :** `AIB_DPA_v1.0_2026.pdf`

### Parties
- Responsable de traitement : le Client (Scale/Enterprise)
- Sous-traitant : TNTECH CONSULTING SAS (SIREN 993 811 157, 6 rue d'Armaille, 75017 Paris)

### Articles couverts
11 articles : définitions, périmètre du traitement, obligations ST, sous-traitants ultérieurs (Supabase/Resend/Anthropic/Netlify/GitHub), transferts internationaux (SCCs), droits des personnes, audit, EU AI Act, résiliation, responsabilité, droit applicable.

### Clause critique (Art. 3.6)
Le Client est seul responsable de la configuration métier des policies custom. TNTECH CONSULTING SAS fournit le moteur sans valider la conformité réglementaire du contenu.

---

## 8. Migration DB — Tracking DPA (`dpa_acceptance_tracking`)

**Colonnes ajoutées à `organizations`** :
- `dpa_accepted_at TIMESTAMPTZ` — date/heure acceptation électronique
- `dpa_version TEXT` — version du DPA (actuellement `'1.0'`)
- `dpa_accepted_by TEXT` — email de l'acceptant
- `dpa_ip_address TEXT` — IP (preuve eIDAS)

**Trigger `enforce_dpa_on_upgrade()`** — bloque upgrade vers Scale/Enterprise si `dpa_accepted_at IS NULL`.

**Vue `admin_dpa_compliance`** — statuts : `OK`, `MISSING`, `OUTDATED`, `NOT_REQUIRED`.

**Décision Pro :** pas de DPA obligatoire au signup, mais clause CGV Art. 9.2 requérant un ATD si usage sur données de tiers.

---

## 9. Mise à jour CGV

**Articles mis à jour ou ajoutés :**
- Art. 2 — Objet : ajout policies déclaratives, policy-dryrun, 14 agents autonomes
- Art. 5 — Plans : plan Scale ajouté avec description correcte, DPA obligatoire Scale/Enterprise formalisé, clause Pro
- Art. 9 — Protection données : reécrit avec 5 sous-articles couvrant DPA, sous-traitance, responsabilité policies, sous-traitants ultérieurs, hébergement
- Art. 10 — EU AI Act : nouvel article (Art. 12/13/14 EU AI Act)
- Art. 11-16 — Restructuration numérotation, mise à jour contacts (contact@aib-tech.fr)

---

## État des Edge Functions après la journée

| Function | Version | Statut |
|----------|---------|--------|
| `passport-create` | v20 | Moteur déclaratif générique |
| `policy-suggest` | v7 | Sanity checker + 5 suggestions |
| `policy-dryrun` | v2 | Fix intersects_all_of (every vs some) |
| `monitoring` | v11 | Actif |
| `cicd-guardian` | v5 | Actif |
| `aib-well-known` | v1 | Actif |

---

## Pending critique avant sortie de bêta

1. **DPA flow dashboard** — page avec case à cocher obligatoire avant paiement Scale/Enterprise (trigger DB déjà en place)
2. **SIREN dans CGV** — remplacer `Paris 17e` par `6 rue d'Armaille, 75017 Paris`
3. **Validation juridique DPA** — avocat RGPD spécialisé (budget 500-2000€)
4. **Redeployer onboarding-agent et feedback-agent** — template email unifié toujours pending
5. **policy-manage PATCH** — endpoint self-service pour activer une custom rule depuis le dashboard
6. **UI dashboard Custom Policies** — onglet dédié pour Scale/Enterprise (voir valid/activated, activer, lien dry-run)

