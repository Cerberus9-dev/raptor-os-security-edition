#!/bin/sh
# Panel load widget payload for xfce4-genmon-plugin. Prints current CPU and
# memory usage as one line so the load is always visible (Kodachi-style).
# Two samples of /proc/stat are needed for an instantaneous CPU value.
set -e

s1=$(awk '/^cpu[ \t]/{print $2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat)
set -- $s1
u1=$1; n1=$2; s3=$3; i1=$4; io1=$5; ir1=$6; si1=$7; st1=$8
sleep 0.3
s2=$(awk '/^cpu[ \t]/{print $2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat)
set -- $s2
u2=$1; n2=$2; s4=$3; i2=$4; io2=$5; ir2=$6; si2=$7; st2=$8

busy1=$((u1 + n1 + s3 + io1 + ir1 + si1 + st1))
busy2=$((u2 + n2 + s4 + io2 + ir2 + si2 + st2))
tot1=$((busy1 + i1))
tot2=$((busy2 + i2))
dt=$((tot2 - tot1))
[ "$dt" -gt 0 ] || dt=1
cpu=$(( (busy2 - busy1) * 100 / dt ))

memtotal=$(awk '/MemTotal/{print $2}' /proc/meminfo)
[ "${memtotal:-0}" -gt 0 ] || memtotal=1
memavail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
mem=$(( (memtotal - memavail) * 100 / memtotal ))

printf "<txt><span fgcolor='#7ec3ff' font_weight='bold'>CPU</span> %s%%   <span fgcolor='#6fe39a' font_weight='bold'>RAM</span> %s%%</txt>\n" "$cpu" "$mem"