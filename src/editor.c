/* Copyright (C) 2000, 2001, 2002, 2003, 2004 Shawn Betts <sabetts@vcn.bc.ca>
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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>

#include "ratpoison.h"

/* bind functions */
static edit_status editor_forward_char (rp_input_line *line);
static edit_status editor_backward_char (rp_input_line *line);
static edit_status editor_forward_word (rp_input_line *line);
static edit_status editor_backward_word (rp_input_line *line);
static edit_status editor_beginning_of_line (rp_input_line *line);
static edit_status editor_end_of_line (rp_input_line *line);
static edit_status editor_delete_char (rp_input_line *line);
static edit_status editor_backward_delete_char (rp_input_line *line);
static edit_status editor_kill_word (rp_input_line *line);
static edit_status editor_backward_kill_word (rp_input_line *line);
static edit_status editor_kill_line (rp_input_line *line);
static edit_status editor_paste_selection (rp_input_line *line);
static edit_status editor_abort (rp_input_line *line);
static edit_status editor_no_action (rp_input_line *line);
static edit_status editor_enter (rp_input_line *line);
static edit_status editor_history_previous (rp_input_line *line);
static edit_status editor_history_next (rp_input_line *line);
static edit_status editor_backward_kill_line (rp_input_line *line);
static edit_status editor_complete_prev (rp_input_line *line);
static edit_status editor_complete_next (rp_input_line *line);

/* default edit action */
static edit_status editor_insert (rp_input_line *line, char *keysym_buf);


#ifdef HAVE_HISTORY
static char *saved_command = NULL;
#endif

typedef struct edit_binding edit_binding;

struct edit_binding
{
  struct rp_key key;
  edit_status (*func)(rp_input_line *);
};

static edit_binding edit_bindings[] =
  { {{XK_g, 		RP_CONTROL_MASK},       editor_abort},
     {{XK_Escape, 	0},          		editor_abort},
     {{XK_f, 		RP_CONTROL_MASK},       editor_forward_char},
     {{XK_Right, 	0},           		editor_forward_char},
     {{XK_b, 		RP_CONTROL_MASK},       editor_backward_char},
     {{XK_Left, 	0},            		editor_backward_char},
     {{XK_f, 		RP_META_MASK},          editor_forward_word},
     {{XK_b, 		RP_META_MASK},          editor_backward_word},
     {{XK_a, 		RP_CONTROL_MASK},       editor_beginning_of_line},
     {{XK_Home, 	0},            		editor_beginning_of_line},
     {{XK_e, 		RP_CONTROL_MASK},       editor_end_of_line},
     {{XK_End, 		0},             	editor_end_of_line},
     {{XK_d, 		RP_CONTROL_MASK},       editor_delete_char},
     {{XK_Delete, 	0},          		editor_delete_char},
     {{XK_BackSpace, 	0},       		editor_backward_delete_char},
     {{XK_BackSpace,	RP_META_MASK},          editor_backward_kill_word},
     {{XK_d, 		RP_META_MASK},          editor_kill_word},
     {{XK_k, 		RP_CONTROL_MASK},       editor_kill_line},
     {{XK_u, 		RP_CONTROL_MASK},       editor_backward_kill_line},
     {{XK_y, 		RP_CONTROL_MASK},  	editor_paste_selection},
     {{XK_p, 		RP_CONTROL_MASK},       editor_history_previous},
     {{XK_Up, 		0},              	editor_history_previous},
     {{XK_n, 		RP_CONTROL_MASK},       editor_history_next},
     {{XK_Down, 	0},            		editor_history_next},
     {{XK_Return, 	0},          		editor_enter},
     {{XK_KP_Enter, 	0},        		editor_enter},
     {{XK_Tab,		0},        		editor_complete_next},
     {{XK_ISO_Left_Tab,	0},        		editor_complete_prev},
     { {0, 		0},                	0} };

rp_input_line *
input_line_new (char *prompt, char *preinput, completion_fn fn)
{
  rp_input_line *line;

  line = xmalloc (sizeof (rp_input_line));
  line->prompt = prompt;
  line->compl = completions_new (fn);

  /* Allocate some memory to start with */
  line->size = strlen (preinput) + 100;
  line->buffer = (char *) xmalloc (line->size);

  /* load in the preinput */
  strcpy (line->buffer, preinput);
  line->position = line->length = strlen (preinput);

  return line;
}

void
input_line_free (rp_input_line *line)
{
  completions_free (line->compl);
  free (line->buffer);
  free (line);
}

edit_status
execute_edit_action (rp_input_line *line, KeySym ch, unsigned int modifier, char *keysym_buf)
{
  struct edit_binding *binding = NULL;
  int found_binding = 0;
  edit_status status;

  for (binding = edit_bindings; binding->func; binding++)
    {
      if (ch == binding->key.sym && modifier == binding->key.state)
        {
          found_binding = 1;
          break;
        }
    }

  if (found_binding)
    status = binding->func (line);
  else if (modifier)
    status = editor_no_action (line);
  else
    status = editor_insert (line, keysym_buf);

  return status;
}

static edit_status
editor_forward_char (rp_input_line *line)
{
  if (line->position < line->length)
    {
      line->position++;
      return EDIT_MOVE;
    }
  else
    return EDIT_NO_OP;

}

static edit_status
editor_backward_char (rp_input_line *line)
{
  if (line->position > 0)
    {
      line->position--;
      return EDIT_MOVE;
    }
  else
    return EDIT_NO_OP;
}

static edit_status
editor_forward_word (rp_input_line *line)
{
  if (line->position < line->length)
    {
      for (; line->position < line->length && !isalnum (line->buffer[line->position]); line->position++);
      for (; line->position < line->length && isalnum (line->buffer[line->position]); line->position++);
    }

  return EDIT_MOVE;
}

static edit_status
editor_backward_word (rp_input_line *line)
{
  if (line->position > 0)
    {
      for (; line->position > 0 && !isalnum (line->buffer[line->position - 1]); line->position--);
      for (; line->position > 0 && isalnum (line->buffer[line->position - 1]); line->position--);
    }

  return EDIT_MOVE;
}

static edit_status
editor_beginning_of_line (rp_input_line *line)
{
  if (line->position > 0)
    line->position = 0;

  return EDIT_MOVE;
}

static edit_status
editor_end_of_line (rp_input_line *line)
{
  if (line->position < line->length)
    line->position = line->length;

  return EDIT_MOVE;
}

static edit_status
editor_delete_char (rp_input_line *line)
{
  int i;

  if (line->position < line->length)
    {
      for (i = line->position; i < line->length; i++)
        line->buffer[i] = line->buffer[i + 1];

      line->length--;
      return EDIT_DELETE;
    }
  else
    return EDIT_NO_OP;
}

static edit_status
editor_backward_delete_char (rp_input_line *line)
{
  int i;

  if (line->position > 0)
    {
      for (i = line->position - 1; i < line->length; i++)
        line->buffer[i] = line->buffer[i + 1];

      line->position--;
      line->length--;
      return EDIT_DELETE;
    }
  else
    return EDIT_NO_OP;
}

static edit_status
editor_kill_word (rp_input_line *line)
{
  int i, diff;
  

  if (line->position < line->length)
    {
      for (i = line->position; i < line->length && !isalnum (line->buffer[i]); i++);
      for (; i < line->length && isalnum (line->buffer[i]); i++);

      diff = i - line->position;

      /* Add the word to the X11 selection. */
      set_nselection (&line->buffer[line->position], diff);
  
      for (i = line->position; i <= line->length - diff; i++)
        line->buffer[i] = line->buffer[i + diff];

      line->length -= diff;
    }

  return EDIT_DELETE;
}

static edit_status
editor_backward_kill_word (rp_input_line *line)
{
  int i, diff;

  if (line->position > 0)
    {
      for (i = line->position; i > 0 && !isalnum (line->buffer[i - 1]); i--);
      for (; i > 0 && isalnum (line->buffer[i - 1]); i--);

      diff = line->position - i;

      line->position = i;

      /* Add the word to the X11 selection. */
      set_nselection (&line->buffer[line->position], diff);

      for (; i <= line->length - diff; i++)
        line->buffer[i] = line->buffer[i + diff];

      line->length -= diff;
    }

  return EDIT_DELETE;
}

static edit_status
editor_kill_line (rp_input_line *line)
{
  if (line->position < line->length)
    {
      /* Add the line to the X11 selection. */
      set_selection (&line->buffer[line->position]);

      line->length = line->position;
      line->buffer[line->length] = 0;
    }

  return EDIT_DELETE;
}

/* Do the dirty work of killing a line backwards. */
static void
backward_kill_line (rp_input_line *line)
{
  int i;

  /* If we're at the beginning, we have nothing to do. */
  if (line->position <= 0)
    return;

  for (i = line->position; i<= line->length; i++)
    line->buffer[i - line->position] = line->buffer[i];

  line->length -= line->position;
  line->position = 0;
}

static edit_status
editor_backward_kill_line (rp_input_line *line)
{
  if (line->position <= 0)
    return EDIT_NO_OP;

  /* Add the line to the X11 selection. */
  set_nselection (line->buffer, line->position);

  backward_kill_line (line);

  return EDIT_DELETE;
}

static edit_status
editor_history_previous (rp_input_line *line)
{
#ifdef HAVE_HISTORY
  char *entry = history_previous ();

  if (entry)
    {
      if (!saved_command)
        {
          line->buffer[line->length] = '\0';
          saved_command = xstrdup (line->buffer);
          PRINT_DEBUG (("saved current command line: \'%s\'\n", saved_command));
        }

      free (line->buffer);
      line->buffer = xstrdup (entry);
      line->length = strlen (line->buffer);
      line->size = line->length + 1;
      line->position = line->length;
      PRINT_DEBUG (("entry: \'%s\'\n", line->buffer));
    }
  else
    {
      PRINT_DEBUG (("- do nothing -\n"));
      return EDIT_NO_OP;
    }

  return EDIT_INSERT;

#else  /* HAVE_HISTORY */

  return EDIT_NO_OP;

#endif /* HAVE_HISTORY */
}

static edit_status
editor_history_next (rp_input_line *line)
{
#ifdef HAVE_HISTORY
  char *entry = history_next ();

  if (entry)
    {
      free (line->buffer);
      line->buffer = xstrdup (entry);
      PRINT_DEBUG (("entry: \'%s\'\n", line->buffer));
    }
  else if (saved_command)
    {
          free (line->buffer);
          line->buffer = saved_command;
          saved_command = NULL;
          PRINT_DEBUG (("restored command line: \'%s\'\n", line->buffer));
    }
  else
    {
      PRINT_DEBUG (("- do nothing -\n"));
          return EDIT_NO_OP;
    }

  line->length = strlen (line->buffer);
  line->size = line->length + 1;
  line->position = line->length;

  return EDIT_INSERT;

#else  /* HAVE_HISTORY */
  return EDIT_NO_OP;
#endif /* HAVE_HISTORY */
}

static edit_status
editor_abort (rp_input_line *line)
{
  return EDIT_ABORT;
}

static edit_status
editor_no_action (rp_input_line *line)
{
  return EDIT_NO_OP;
}

static edit_status
editor_insert (rp_input_line *line, char *keysym_buf)
{
  int nbytes;
  int i;

  PRINT_DEBUG (("keysym_buf: '%s'\n", keysym_buf));

  nbytes = strlen (keysym_buf);
  if (line->length + nbytes > line->size - 1)
    {
      line->size += nbytes + 100;
      line->buffer = xrealloc (line->buffer, line->size);
    }

  for (i = line->length + nbytes; i > line->position; i--)
    line->buffer[i] = line->buffer[i - nbytes];

  strncpy (&line->buffer[line->position], keysym_buf, nbytes);

  line->length += nbytes;
  line->position += nbytes;

  PRINT_DEBUG (("line->buffer: '%s'\n", line->buffer));

  return EDIT_INSERT;
}

static edit_status
editor_enter (rp_input_line *line)
{
#ifdef HAVE_HISTORY
  int result;
  char *expansion;
#endif

  line->buffer[line->length] = '\0';
#ifdef HAVE_HISTORY
  result = history_expand_line (line->buffer, &expansion);

  PRINT_DEBUG (("History Expansion - result: %d\n", result));
  PRINT_DEBUG (("History Expansion - expansion: \'%s\'\n", expansion));

  if (result == -1 || result == 2)
    {
      marked_message_printf (0, 0, "%s", expansion);
      free (expansion);
      return EDIT_ABORT;
    }
  else /* result == 0 || result == 1 */
    { 
      history_add (expansion);
      line->buffer = expansion;
    }
#endif /* HAVE_HISTORY */

  return EDIT_DONE;
}

static edit_status
editor_paste_selection (rp_input_line *line)
{
  char *text;
  text = get_selection();
  if (text)
    {
      editor_insert(line, text);
      free (text);
      return EDIT_INSERT;
    }
  else
    return EDIT_NO_OP;
}

static edit_status
editor_complete (rp_input_line *line, int direction)
{
  char *tmp;
  char *s;

  /* Create our partial string that will be used for completion. It is
     the characters up to the position of the cursor. */
  tmp = xmalloc ((line->position + 1) * sizeof (char));
  strncpy (tmp, line->buffer, line->position);
  tmp[line->position] = '\0';

  /* We don't need to free s because it's a string from the completion
     list. */
  s = completions_complete (line->compl, tmp, direction);
  free (tmp);

  if (s == NULL)
    return EDIT_NO_OP;

  /* Insert the completion. */
  backward_kill_line (line);
  editor_insert (line, s);

  return EDIT_COMPLETE;
}

static edit_status
editor_complete_next (rp_input_line *line)
{
  return editor_complete (line, COMPLETION_NEXT);
}

static edit_status
editor_complete_prev (rp_input_line *line)
{
  return editor_complete (line, COMPLETION_PREVIOUS);
}
