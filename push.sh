#!/usr/bin/env bash
# ============================================================================
#  OpenOS Cloud — güvenli yayınlama betiği
#
#  Bu betik HİÇBİR GİZLİ DEĞER SAKLAMAZ. Token'ı üç kanaldan biriyle alır ve
#  hiçbirinde düz metin olarak diske yazmaz:
#
#    1) gh (GitHub CLI)  — önerilen. Token'ı gh'ın kendi güvenli deposunda tutar.
#    2) SSH anahtarı     — token hiç kullanılmaz.
#    3) GITHUB_TOKEN     — yalnızca o anki kabuk ortamında yaşar, dosyaya yazılmaz.
#
#  Kullanım:  ./push.sh ["commit mesajı"]
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; OFF=$'\e[0m'; B=$'\e[1m'
ok()   { echo "${GRN}✓${OFF} $*"; }
warn() { echo "${YEL}!${OFF} $*"; }
die()  { echo "${RED}✗${OFF} $*" >&2; exit 1; }
step() { echo; echo "${B}▸ $*${OFF}"; }

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
REMOTE="${REMOTE:-origin}"

# ---------------------------------------------------------------- 1. sır taraması
step "Gizli değer taraması"
LEAK_PATTERNS='github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,}'
# Yalnızca commit edilecek (takip edilen + eklenmiş) dosyalara bakılır.
FILES="$(git ls-files; git diff --cached --name-only)"
HITS=""
while IFS= read -r f; do
  [ -f "$f" ] || continue
  case "$f" in push.sh) continue ;; esac
  if grep -InEq "$LEAK_PATTERNS" "$f" 2>/dev/null; then
    HITS="$HITS$f"$'\n'
  fi
done <<< "$(printf '%s\n' "$FILES" | sort -u)"

if [ -n "$HITS" ]; then
  echo "$RED$B  DURDURULDU — depoya girecek dosyalarda gizli değer kalıbı bulundu:$OFF"
  printf '%s' "$HITS" | sed 's/^/    /'
  die "Bu dosyaları temizleyin. Sızan bir token'ı silmek yetmez — GitHub'dan iptal edin."
fi
ok "gizli değer kalıbı yok"

for f in .dev.vars .env; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    die "$f depoya eklenmiş. 'git rm --cached $f' ile çıkarın; .gitignore zaten kapsıyor."
  fi
done
ok ".dev.vars / .env takip edilmiyor"

# ---------------------------------------------------------------- 2. kimlik
step "Kimlik doğrulama"
AUTH=""
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  AUTH="gh"
  gh auth setup-git >/dev/null 2>&1 || true
  ok "gh ile giriş yapılmış ($(gh api user --jq .login 2>/dev/null || echo '?'))"
elif git remote get-url "$REMOTE" | grep -q '^git@'; then
  AUTH="ssh"
  ok "SSH uzak adresi kullanılıyor"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH="env"
  ok "GITHUB_TOKEN ortam değişkeninden okunacak (diske yazılmaz)"
else
  cat <<TXT

  ${YEL}Kimlik tanımlı değil.${OFF} Aşağıdakilerden birini ${B}bir kez${OFF} yapın:

  ${B}A) GitHub CLI — önerilen${OFF}
     ${DIM}Token'ı gh kendi güvenli deposunda tutar, bir daha sormaz.${OFF}
       gh auth login
     ${DIM}Sorular: GitHub.com → HTTPS → Y (git kimliği) → tarayıcı ya da token${OFF}

  ${B}B) SSH anahtarı — token hiç kullanılmaz${OFF}
       ssh-keygen -t ed25519 -C "m3sto"
       cat ~/.ssh/id_ed25519.pub      ${DIM}# çıktıyı GitHub → Settings → SSH keys'e ekleyin${OFF}
       git remote set-url $REMOTE git@github.com:m3sto/openos-cloud.git

  ${B}C) Tek seferlik ortam değişkeni${OFF}
     ${DIM}Yalnızca o kabukta yaşar, hiçbir dosyaya yazılmaz:${OFF}
       read -rs GITHUB_TOKEN && export GITHUB_TOKEN && ./push.sh
       ${DIM}(read -rs: yazdığınız token ekranda görünmez ve geçmişe düşmez)${OFF}

TXT
  die "kimlik yok"
fi

# ---------------------------------------------------------------- 3. commit
step "Değişiklikler"
if [ -n "$(git status --porcelain)" ]; then
  git status --short | sed 's/^/    /'
  MSG="${1:-güncelleme: $(date +%Y-%m-%d\ %H:%M)}"
  git add -A
  git commit -q -m "$MSG"
  ok "commit: $MSG"
else
  ok "çalışma ağacı temiz"
fi

# ---------------------------------------------------------------- 4. senkron
step "Uzak depo ile eşitleme"
git fetch "$REMOTE" --quiet
if git rev-parse --verify --quiet "$REMOTE/$BRANCH" >/dev/null; then
  if git merge-base --is-ancestor "$REMOTE/$BRANCH" HEAD; then
    ok "ileri sarma — rebase gerekmiyor"
  else
    warn "uzakta yeni commit var, üzerine rebase ediliyor"
    git tag -f "pre-push-$(date +%s)" HEAD >/dev/null
    git rebase "$REMOTE/$BRANCH" || die "rebase çakıştı. Çözün, 'git rebase --continue' deyin, betiği tekrar çalıştırın. Geri dönmek için: git rebase --abort"
    ok "rebase tamam"
  fi
else
  ok "uzakta bu dal yok, ilk gönderim"
fi

# ---------------------------------------------------------------- 5. push
step "Gönderiliyor"
case "$AUTH" in
  env)
    # Token yalnızca bu tek komutun ortamında; yapılandırmaya yazılmaz.
    git -c credential.helper= \
        -c credential.helper='!f() { echo username=x-access-token; echo "password=${GITHUB_TOKEN}"; }; f' \
        push -u "$REMOTE" "$BRANCH"
    ;;
  *)
    git push -u "$REMOTE" "$BRANCH"
    ;;
esac

ok "gönderildi → $(git remote get-url "$REMOTE" | sed 's#https://[^@]*@#https://#')"
echo
echo "  Pano:  ${B}https://m3sto.github.io/openos-cloud/${OFF}"
echo "  ${DIM}Pages açık değilse: Settings → Pages → Deploy from a branch → main / docs${OFF}"
