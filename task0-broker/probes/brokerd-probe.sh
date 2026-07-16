#!/bin/bash
# Runs AS _ccfido under launchd (no GUI session). Proves: (1) reach the USB key
# to sign; (3-owner) toggle uchg on an owned file. Writes results to a log the
# driver reads. Expects to be armed then touched by the human.
set -u
SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
VERIFY=/usr/bin/ssh-keygen
KEYDIR=/var/ccfido
NS='cc-fido-gate@example.test'; PRIN=gate-principal
OUT=/var/ccfido/q1.log; MSG='broker-gate Q1 daemon sign'
{
  echo "=== daemon whoami: $(id) ==="
  echo "=== (3-owner) uchg toggle on an owned file ==="
  F=/var/ccfido/ownedfile; echo v > "$F"
  chflags uchg "$F" && echo "set uchg OK" || echo "set uchg FAIL"
  ( echo x > "$F" ) 2>/dev/null && echo "UNEXPECTED: wrote while uchg" || echo "write-while-uchg denied OK"
  chflags nouchg "$F" && echo "clear uchg OK (owner, no root)" || echo "clear uchg FAIL"
  echo "=== (1) sign against USB key — TOUCH EXPECTED ==="
  printf '%s' "$MSG" | "$SIGN" -Y sign -f "$KEYDIR/gate_sk" -n "$NS" > /var/ccfido/q1.sig 2>/var/ccfido/q1.sign.err
  echo "sign rc=$?"; cat /var/ccfido/q1.sign.err
  if grep -q 'BEGIN SSH SIGNATURE' /var/ccfido/q1.sig 2>/dev/null; then
    printf '%s' "$MSG" | "$VERIFY" -Y verify -f "$KEYDIR/allowed_signers" -I "$PRIN" -n "$NS" -s /var/ccfido/q1.sig \
      && echo "VERDICT: GREEN daemon signed+verified" || echo "VERDICT: RED signed but verify failed"
  else
    echo "VERDICT: RED daemon could NOT sign (device not found / TCC denied) — architecture rework"
  fi
} > "$OUT" 2>&1
