/* Read kdb input from the user.
 * Copyright (C) 2000, 2001, 2002, 2003, 2004 Shawn Betts <sabetts@vcn.bc.ca>
 *
 * This file is part of ratpoison.
 *
 * ratpoison is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * ratpoison is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307 USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/Xutil.h>

#include "ratpoison.h"

/* Convert an X11 modifier mask to the rp modifier mask equivalent, as
   best it can (the X server may not have a hyper key defined, for
   instance). */
unsigned int
x11_mask_to_rp_mask (unsigned int mask)
{
  unsigned int result = 0;

  PRINT_DEBUG (("x11 mask = %x\n", mask));

  result |= mask & ShiftMask ? RP_SHIFT_MASK:0;
  result |= mask & ControlMask ? RP_CONTROL_MASK:0;
  result |= mask & rp_modifier_info.meta_mod_mask ? RP_META_MASK:0;
  result |= mask & rp_modifier_info.alt_mod_mask ? RP_ALT_MASK:0;
  result |= mask & rp_modifier_info.hyper_mod_mask ? RP_HYPER_MASK:0;
  result |= mask & rp_modifier_info.super_mod_mask ? RP_SUPER_MASK:0;

  PRINT_DEBUG (("rp mask = %x\n", mask));

  return result;
}

/* Convert an rp modifier mask to the x11 modifier mask equivalent, as
   best it can (the X server may not have a hyper key defined, for
   instance). */
unsigned int
rp_mask_to_x11_mask (unsigned int mask)
{
  unsigned int result = 0;

  PRINT_DEBUG (("rp mask = %x\n", mask));

  result |= mask & RP_SHIFT_MASK ? ShiftMask:0;
  result |= mask & RP_CONTROL_MASK ? ControlMask:0;
  result |= mask & RP_META_MASK ? rp_modifier_info.meta_mod_mask:0;
  result |= mask & RP_ALT_MASK ? rp_modifier_info.alt_mod_mask:0;
  result |= mask & RP_HYPER_MASK ? rp_modifier_info.hyper_mod_mask:0;
  result |= mask & RP_SUPER_MASK ? rp_modifier_info.super_mod_mask:0;

  PRINT_DEBUG (("x11 mask = %x\n", result));

  return result;
}


/* Figure out what keysyms are attached to what modifiers */
void
update_modifier_map ()
{
  unsigned int modmasks[] = 
    { Mod1Mask, Mod2Mask, Mod3Mask, Mod4Mask, Mod5Mask };
  int row, col;	/* The row and column in the modifier table.  */
  XModifierKeymap *mods;

  rp_modifier_info.meta_mod_mask = 0;
  rp_modifier_info.alt_mod_mask = 0;
  rp_modifier_info.super_mod_mask = 0;
  rp_modifier_info.hyper_mod_mask = 0;
  rp_modifier_info.num_lock_mask = 0;
  rp_modifier_info.scroll_lock_mask = 0;

  mods = XGetModifierMapping (dpy);

  for (row=3; row < 8; row++)
    for (col=0; col < mods->max_keypermod; col++)
      {
	KeyCode code = mods->modifiermap[(row * mods->max_keypermod) + col];
	
	if (code == 0) continue;
	
	switch (XKeycodeToKeysym(dpy, code, 0))
	  {
	  case XK_Meta_L:
	  case XK_Meta_R:
	    rp_modifier_info.meta_mod_mask |= modmasks[row - 3];
	    PRINT_DEBUG (("Found Meta on %d\n",
			 rp_modifier_info.meta_mod_mask));
	    break;

	  case XK_Alt_L:
	  case XK_Alt_R:
	    rp_modifier_info.alt_mod_mask |= modmasks[row - 3];
	    PRINT_DEBUG (("Found Alt on %d\n",
			 rp_modifier_info.alt_mod_mask));
	    break;

	  case XK_Super_L:
	  case XK_Super_R:
	    rp_modifier_info.super_mod_mask |= modmasks[row - 3];
	    PRINT_DEBUG (("Found Super on %d\n",
			 rp_modifier_info.super_mod_mask));
	    break;

	  case XK_Hyper_L:
	  case XK_Hyper_R:
	    rp_modifier_info.hyper_mod_mask |= modmasks[row - 3];
	    PRINT_DEBUG (("Found Hyper on %d\n",
			 rp_modifier_info.hyper_mod_mask));
	    break;

	  case XK_Num_Lock:
	    rp_modifier_info.num_lock_mask |= modmasks[row - 3];
	    PRINT_DEBUG (("Found NumLock on %d\n", 
			 rp_modifier_info.num_lock_mask));
	    break;

	  case XK_Scroll_Lock:
	    rp_modifier_info.scroll_lock_mask |= modmasks[row - 3];
	    PRINT_DEBUG (("Found ScrollLock on %d\n", 
			 rp_modifier_info.scroll_lock_mask));
	    break;
	  default:
	    break;
	  }
      }
  
  /* Stolen from Emacs 21.0.90 - xterm.c */
  /* If we couldn't find any meta keys, accept any alt keys as meta keys.  */
  if (! rp_modifier_info.meta_mod_mask)
    {
      rp_modifier_info.meta_mod_mask = rp_modifier_info.alt_mod_mask;
      rp_modifier_info.alt_mod_mask = 0;
    }

  /* If some keys are both alt and meta,
     make them just meta, not alt.  */
  if (rp_modifier_info.alt_mod_mask & rp_modifier_info.meta_mod_mask)
    {
      rp_modifier_info.alt_mod_mask &= ~rp_modifier_info.meta_mod_mask;
    }

  XFreeModifiermap (mods);
}

/* we need a keycode + modifier to generate the proper keysym (such as
   @). */
static void
keysym_to_keycode_mod (KeySym keysym, KeyCode *code, unsigned int *mod)
{
  KeySym lower, upper;

  *mod = 0;
  *code = XKeysymToKeycode (dpy, keysym);
  lower = XKeycodeToKeysym (dpy, *code, 0);
  upper = XKeycodeToKeysym (dpy, *code, 1);
  /* If you need to press shift to get the keysym, add the shift
     mask. */
  if (upper == keysym && lower != keysym)
    *mod = ShiftMask;
}

/* Grab the key while ignoring annoying modifier keys including
   caps lock, num lock, and scroll lock. */
void
grab_key (KeySym keysym, unsigned int modifiers, Window grab_window)
{
  unsigned int mod_list[8];
  int i;
  KeyCode keycode;
  unsigned int mod;
      
  /* Convert to a modifier mask that X Windows will understand. */
  modifiers = rp_mask_to_x11_mask (modifiers);
  keysym_to_keycode_mod (keysym, &keycode, &mod);
  PRINT_DEBUG (("keycode_mod: %ld %d %d\n", keysym, keycode, mod));
  modifiers |= mod;

  /* Create a list of all possible combinations of ignored
     modifiers. Assumes there are only 3 ignored modifiers. */
  mod_list[0] = 0;
  mod_list[1] = LockMask;
  mod_list[2] = rp_modifier_info.num_lock_mask;
  mod_list[3] = mod_list[1] | mod_list[2];
  mod_list[4] = rp_modifier_info.scroll_lock_mask;
  mod_list[5] = mod_list[1] | mod_list[4];
  mod_list[6] = mod_list[2] | mod_list[4];
  mod_list[7] = mod_list[1] | mod_list[2] | mod_list[4];

  /* Grab every combination of ignored modifiers. */
  for (i=0; i<8; i++)
    {
      XGrabKey(dpy, keycode, modifiers | mod_list[i],
	       grab_window, True, GrabModeAsync, GrabModeAsync);
    }
}


/* Return the name of the keysym. caller must free returned pointer */
char *
keysym_to_string (KeySym keysym, unsigned int modifier)
{
  static char *null_string = "NULL"; /* A NULL string. */
  struct sbuf *name;
  char *tmp;

  name = sbuf_new (0);

  if (modifier & RP_SHIFT_MASK) sbuf_concat (name, "S-");
  if (modifier & RP_CONTROL_MASK) sbuf_concat (name, "C-");
  if (modifier & RP_META_MASK) sbuf_concat (name, "M-");
  if (modifier & RP_ALT_MASK) sbuf_concat (name, "A-");
  if (modifier & RP_HYPER_MASK) sbuf_concat (name, "H-");
  if (modifier & RP_SUPER_MASK) sbuf_concat (name, "s-");
    
  /* On solaris machines (perhaps other machines as well) this call
     can return NULL. In this case use the "NULL" string. */
  tmp = XKeysymToString (keysym);
  if (tmp == NULL)
    tmp = null_string;

  sbuf_concat (name, tmp);

  /* Eat the nut and throw away the shells. */
  tmp = sbuf_get (name);
  free (name);

  return tmp;
}

/* Cooks a keycode + modifier into a keysym + modifier. This should be
   used anytime meaningful key information is to be extracted from a
   KeyPress or KeyRelease event. 

   returns the number of bytes in keysym_name. If you are not
   interested in the keysym name pass in NULL for keysym_name and 0
   for len. */
int
cook_keycode (XKeyEvent *ev, KeySym *keysym, unsigned int *mod, char *keysym_name, int len, int ignore_bad_mods)
{
  int nbytes;
  int shift = 0;
  KeySym lower, upper;
 
  if (ignore_bad_mods)
    {
      ev->state &= ~(LockMask
		     | rp_modifier_info.num_lock_mask
		     | rp_modifier_info.scroll_lock_mask);
    }

  if (len > 0) len--;
  nbytes =  XLookupString (ev, keysym_name, len, keysym, NULL);

  /* Null terminate the string (not all X servers do it for us). */
  if (keysym_name) {
    keysym_name[nbytes] = '\0';
  }

  /* Find out if XLookupString gobbled the shift modifier */
  if (ev->state & ShiftMask)
    {
      lower = XKeycodeToKeysym (dpy, ev->keycode, 0);
      upper = XKeycodeToKeysym (dpy, ev->keycode, 1);
      /* If the keysym isn't affected by the shift key, then keep the
	 shift modifier. */
      if (lower == upper)
	shift = ShiftMask;
    }

  *mod = ev->state;
  *mod &= (rp_modifier_info.meta_mod_mask
	   | rp_modifier_info.alt_mod_mask
	   | rp_modifier_info.hyper_mod_mask
	   | rp_modifier_info.super_mod_mask
	   | ControlMask
	   | shift);

  return nbytes;
}

int
read_key (KeySym *keysym, unsigned int *modifiers, char *keysym_name, int len)
{
  XEvent ev;
  int nbytes;

  /* Read a key from the keyboard. */
  do
    {
      XMaskEvent (dpy, KeyPressMask, &ev);
      *modifiers = ev.xkey.state;
      nbytes = cook_keycode (&ev.xkey, keysym, modifiers, keysym_name, len, 0);
    } while (IsModifierKey (*keysym));

  return nbytes;
}

static void
update_input_window (rp_screen *s, rp_input_line *line)
{
  int 	prompt_width = XTextWidth (defaults.font, line->prompt, strlen (line->prompt));
  int 	input_width  = XTextWidth (defaults.font, line->buffer, line->length);
  int 	total_width;
  GC lgc;
  XGCValues gv;
  int height;

  total_width = defaults.bar_x_padding * 2 + prompt_width + input_width + MAX_FONT_WIDTH (defaults.font);
  height = (FONT_HEIGHT (defaults.font) + defaults.bar_y_padding * 2);

  if (total_width < defaults.input_window_size + prompt_width)
    {
      total_width = defaults.input_window_size + prompt_width;
    }

  XMoveResizeWindow (dpy, s->input_window, 
		     bar_x (s, total_width), bar_y (s, height), total_width,
 		     (FONT_HEIGHT (defaults.font) + defaults.bar_y_padding * 2));

  XClearWindow (dpy, s->input_window);
  XSync (dpy, False);

  XDrawString (dpy, s->input_window, s->normal_gc, 
 	       defaults.bar_x_padding, 
	       defaults.bar_y_padding + defaults.font->max_bounds.ascent,
	       line->prompt, 
	       strlen (line->prompt));
 
  XDrawString (dpy, s->input_window, s->normal_gc, 
 	       defaults.bar_x_padding + prompt_width,
	       defaults.bar_y_padding + defaults.font->max_bounds.ascent,
	       line->buffer, 
	       line->length);

  gv.function = GXxor;
  gv.foreground = s->fg_color ^ s->bg_color;
  lgc = XCreateGC (dpy, s->input_window, GCFunction | GCForeground, &gv);

  /* Draw a cheap-o cursor - MkII */
  XFillRectangle (dpy, s->input_window, lgc, 
		  defaults.bar_x_padding + prompt_width + XTextWidth (defaults.font, line->buffer, line->position),
		  defaults.bar_y_padding, 
		  XTextWidth (defaults.font, &line->buffer[line->position], 1),
		  FONT_HEIGHT (defaults.font));

  XFlush (dpy);
  XFreeGC (dpy, lgc);
}

void
ring_bell ()
{
#ifdef VISUAL_BELL
  GC lgc;
  XGCValues gv;
  XWindowAttributes attr;
  rp_screen *s = current_screen ();

  XGetWindowAttributes (dpy, s->input_window, &attr);

  gv.function = GXxor;
  gv.foreground = s->fg_color ^ s->bg_color;
  lgc = XCreateGC (dpy, s->input_window, GCFunction | GCForeground, &gv);

  XFillRectangle (dpy, s->input_window, lgc, 0, 0, attr.width, attr.height);
  XFlush (dpy);

#ifdef HAVE_USLEEP
  usleep (15000);
#else
  {
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 15000;
    select (0, NULL, NULL, NULL, &tv);
  }
#endif
  XFillRectangle (dpy, s->input_window, lgc, 0, 0, attr.width, attr.height);
  XFlush (dpy);
  XFreeGC (dpy, lgc);
#else
  XBell (dpy, 0);
#endif
}

char *
get_input (char *prompt, completion_fn fn)
{
  return get_more_input (prompt, "", fn);
}

char *
get_more_input (char *prompt, char *preinput, 
		completion_fn compl_fn)
{
  /* Emacs 21 uses a 513 byte string to store the keysym name. */
  char keysym_buf[513];	
  int keysym_bufsize = sizeof (keysym_buf);
  int nbytes;
  rp_screen *s = current_screen ();
  KeySym ch;
  unsigned int modifier;
  rp_input_line *line;
  char *final_input;
  edit_status status;

#ifdef HAVE_READLINE_HISTORY_H
  history_reset();
#endif /* HAVE_READLINE_HISTORY_H */

  /* Create our line structure */
  line = input_line_new (prompt, preinput, compl_fn);

  /* We don't want to draw overtop of the program bar. */
  hide_bar (s);

  XMapWindow (dpy, s->input_window);
  XRaiseWindow (dpy, s->input_window);
  XClearWindow (dpy, s->input_window);
  XSync (dpy, False);

  update_input_window (s, line);

  XGrabKeyboard (dpy, s->input_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

  for (;;)
    {
      nbytes = read_key (&ch, &modifier, keysym_buf, keysym_bufsize);
      modifier = x11_mask_to_rp_mask (modifier);
      PRINT_DEBUG (("ch = %ld, modifier = %d, keysym_buf = %s, keysym_bufsize = %d\n", 
		    ch, modifier, keysym_buf, keysym_bufsize));
      status = execute_edit_action (line, ch, modifier, keysym_buf);

      if (status == EDIT_DELETE || status == EDIT_INSERT || status == EDIT_MOVE
	  || status == EDIT_COMPLETE)
        {
	  /* If the text changed (and we didn't just complete
	     something) then set the virgin bit. */
	  if (status != EDIT_COMPLETE)
	    line->compl->virgin = 1;
	  /* In all cases, we need to redisplay the input string. */
          update_input_window (s, line);
        }
      else if (status == EDIT_NO_OP)
        {
          ring_bell ();
        }
      else if (status == EDIT_ABORT)
        {
          final_input = NULL;
          break;
        }
      else if (status == EDIT_DONE)
        {
          final_input = xstrdup (line->buffer);
          break;
        }
    }

  /* Clean up our line structure */
  input_line_free (line);

  /* Revert focus. */
  XUngrabKeyboard (dpy, CurrentTime);
  XUnmapWindow (dpy, s->input_window);

  return final_input;
}

char *
get_password (char *prompt, completion_fn fn)
{
  return get_even_more_input (prompt, "", fn);
}
