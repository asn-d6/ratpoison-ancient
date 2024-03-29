#!/bin/sh
#
# Copyright (C) 2003 Shawn Betts
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
#
# Split the current frame into 16 little frames. This is an example of
# how to script ratpoison.

RATPOISON=ratpoison

# $RATPOISON -c only

#split into 4 frames

$RATPOISON -c split
$RATPOISON -c vsplit
$RATPOISON -c focusdown
$RATPOISON -c vsplit

# split each new frame into 4

$RATPOISON -c split
$RATPOISON -c vsplit
$RATPOISON -c focusdown
$RATPOISON -c vsplit

$RATPOISON -c focusup
$RATPOISON -c focusup

$RATPOISON -c split
$RATPOISON -c vsplit
$RATPOISON -c focusdown
$RATPOISON -c vsplit

$RATPOISON -c focusright
$RATPOISON -c focusright

$RATPOISON -c split
$RATPOISON -c vsplit
$RATPOISON -c focusdown
$RATPOISON -c vsplit

$RATPOISON -c focusdown

$RATPOISON -c split
$RATPOISON -c vsplit
$RATPOISON -c focusdown
$RATPOISON -c vsplit
