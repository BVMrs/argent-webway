#!/bin/sh
# Part B summary: per design x profile x R-off x M-drain, max over timer (PerEnv/PerDest) and hand-off failure (0/2 %).
awk -F'|' '/^D[0-3][a-z]? / && $1 !~ /\// {
  split($1,a," "); key=sprintf("%-15s %-10s Roff=%-5s M=%-4s", a[1]" "a[2], a[4], a[5], a[6]);
  split($2,b," ");
  if (!(key in seen)) { order[++n]=key; seen[key]=1 }
  if (b[1]>st[key]) st[key]=b[1]; if (b[2]>co[key]) co[key]=b[2]; if (b[4]>lo[key]) lo[key]=b[4]; if (b[5]>xe[key]) xe[key]=b[5]
} END { printf "%-44s %8s %9s %7s %9s\n","design         profile    R-off      M-drain","started%","complete%","lost%","x-exp%";
  for (i=1;i<=n;i++){k=order[i]; printf "%-44s %8.2f %9.3f %7.3f %9.3f\n",k,st[k],co[k],lo[k],xe[k]} }' "$1"
