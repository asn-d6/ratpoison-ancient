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

#include <unistd.h>
#include <sys/wait.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>

#include "ratpoison.h"


#define ARG_STRING(elt) args[elt]->string
#define ARG(elt, type)  args[elt]->arg.type

struct set_var
{
  char *var;
  cmdret *(*set_fn)(struct cmdarg **);
  int nargs;
  struct argspec *args;
  struct list_head node;
};

static cmdret * set_resizeunit (struct cmdarg **args);
static cmdret * set_wingravity (struct cmdarg **args);
static cmdret * set_transgravity (struct cmdarg **args);
static cmdret * set_maxsizegravity (struct cmdarg **args);
static cmdret * set_bargravity (struct cmdarg **args);
static cmdret * set_font (struct cmdarg **args);
static cmdret * set_padding (struct cmdarg **args);
static cmdret * set_border (struct cmdarg **args);
static cmdret * set_barborder (struct cmdarg **args);
static cmdret * set_inputwidth (struct cmdarg **args);
static cmdret * set_waitcursor (struct cmdarg **args);
static cmdret * set_winfmt (struct cmdarg **args);
static cmdret * set_winname (struct cmdarg **args);
static cmdret * set_fgcolor (struct cmdarg **args);
static cmdret * set_bgcolor (struct cmdarg **args);
static cmdret * set_barpadding (struct cmdarg **args);
static cmdret * set_winliststyle (struct cmdarg **args);
static cmdret * set_framesels (struct cmdarg **args);
static cmdret * set_maxundos (struct cmdarg **args);

LIST_HEAD(set_vars);

static void
add_set_var (char *name, cmdret * (*fn)(struct cmdarg **), int nargs, ...)
{
  int i = 0;
  struct set_var *var;
  va_list va;

  var = xmalloc (sizeof (struct set_var));
  var->var = name;
  var->set_fn = fn;
  var->nargs = nargs;
  var->args = xmalloc(sizeof(struct argspec) * nargs);
  
  /* Fill var->args */
  va_start(va, nargs);
  for (i=0; i<nargs; i++)
    {
      var->args[i].prompt = va_arg(va, char*);
      var->args[i].type = va_arg(va, int);
    }
  va_end(va);

  list_add (&var->node, &set_vars);
}

void
init_set_vars()
{
  add_set_var ("resizeunit", set_resizeunit, 1, "", arg_NUMBER);
  add_set_var ("maxundos", set_maxundos, 1, "", arg_NUMBER);
  add_set_var ("wingravity", set_wingravity, 1, "", arg_GRAVITY);
  add_set_var ("transgravity", set_transgravity, 1, "", arg_GRAVITY);
  add_set_var ("maxsizegravity", set_maxsizegravity, 1, "", arg_GRAVITY);
  add_set_var ("bargravity", set_bargravity, 1, "", arg_GRAVITY);
  add_set_var ("font", set_font, 1, "", arg_STRING);
  add_set_var ("padding", set_padding, 4, 
	       "", arg_NUMBER, "", arg_NUMBER, "", arg_NUMBER, "", arg_NUMBER);
  add_set_var ("border", set_border, 1, "", arg_NUMBER);
  add_set_var ("barborder", set_barborder, 1, "", arg_NUMBER);
  add_set_var ("inputwidth", set_inputwidth, 1, "", arg_NUMBER);
  add_set_var ("waitcursor", set_waitcursor, 1, "", arg_NUMBER);
  add_set_var ("winfmt", set_winfmt, 1, "", arg_REST);
  add_set_var ("winname", set_winname, 1, "", arg_STRING);
  add_set_var ("fgcolor", set_fgcolor, 1, "", arg_STRING);
  add_set_var ("bgcolor", set_bgcolor, 1, "", arg_STRING);
  add_set_var ("barpadding", set_barpadding, 2, "", arg_NUMBER, "", arg_NUMBER);
  add_set_var ("winliststyle", set_winliststyle, 1, "", arg_STRING);
  add_set_var ("framesels", set_framesels, 1, "", arg_STRING);
}

/* rp_keymaps is ratpoison's list of keymaps. */
LIST_HEAD(rp_keymaps);
LIST_HEAD(user_commands);

/* i_nrequired is the number required when called
   interactively. ni_nrequired is when called non-interactively. */
static void
add_command (char *name, cmdret * (*fn)(int, struct cmdarg **), int nargs, int i_nrequired, int ni_nrequired, ...)
{
  int i = 0;
  struct user_command *cmd;
  va_list va;

  cmd = xmalloc (sizeof (struct user_command));
  cmd->name = name;
  cmd->func = fn;
  cmd->num_args = nargs;
  cmd->ni_required_args = ni_nrequired;
  cmd->i_required_args = i_nrequired;
  cmd->args = xmalloc(sizeof(struct argspec) * nargs);
  
  /* Fill cmd->args */
  va_start(va, ni_nrequired);
  for (i=0; i<nargs; i++)
    {
      cmd->args[i].prompt = va_arg(va, char*);
      cmd->args[i].type = va_arg(va, int);
    }
  va_end(va);

  list_add (&cmd->node, &user_commands);
}

void
init_user_commands()
{
  /*@begin (tag required for genrpbindings) */
  add_command ("abort",		cmd_abort,	0, 0, 0);
  add_command ("addhook",	cmd_addhook,	2, 2, 2,
	       "Hook: ", arg_HOOK,
	       "Command: ", arg_REST);
  add_command ("alias",		cmd_alias,	2, 2, 2,
	       "Alias: ", arg_STRING,
	       "Command: ", arg_REST);
  add_command ("banish",	cmd_banish,	0, 0, 0);
  add_command ("chdir",		cmd_chdir,	1, 0, 0,
	       "Dir: ", arg_REST);
  add_command ("clrunmanaged",	cmd_clrunmanaged, 0, 0, 0);
  add_command ("colon",		cmd_colon,	1, 0, 0,
	       "", arg_REST);
  add_command ("curframe",	cmd_curframe,	0, 0, 0);
  add_command ("definekey",	cmd_definekey,	3, 3, 3,
	       "Keymap: ", arg_KEYMAP,
	       "Key: ", arg_KEY,
	       "Command: ", arg_REST);
  add_command ("undefinekey",	cmd_undefinekey, 2, 2, 2,
	       "Keymap: ", arg_KEYMAP,
	       "Key: ", arg_KEY);
  add_command ("delete",	cmd_delete,	0, 0, 0);
  add_command ("delkmap",	cmd_delkmap,	1, 1, 1,
	       "Keymap: ", arg_KEYMAP);
  add_command ("echo",		cmd_echo,	1, 1, 1,
	       "Echo: ", arg_RAW);
  add_command ("escape",	cmd_escape,	1, 1, 1,
	       "Key: ", arg_KEY);
  add_command ("exec",		cmd_exec,	1, 1, 1, 
	       "/bin/sh -c ", arg_SHELLCMD);
  add_command ("fdump",		cmd_fdump,	1, 0, 0,
	       "", arg_NUMBER);
  add_command ("focus",		cmd_next_frame,	0, 0, 0);
  add_command ("focusprev",	cmd_prev_frame,	0, 0, 0);
  add_command ("focusdown",	cmd_focusdown,	0, 0, 0);
  add_command ("focuslast",	cmd_focuslast,	0, 0, 0);
  add_command ("focusleft",	cmd_focusleft,	0, 0, 0);
  add_command ("focusright",	cmd_focusright,	0, 0, 0);
  add_command ("focusup",	cmd_focusup,	0, 0, 0);
  add_command ("frestore",	cmd_frestore,	1, 1, 1,
	       "Frames: ", arg_REST);
  add_command ("fselect",	cmd_fselect,	1, 1, 1,
	       "", arg_FRAME);
  add_command ("gdelete",	cmd_gdelete,	1, 0, 0,
 	       "Group:", arg_GROUP);
  add_command ("getenv",	cmd_getenv,	1, 1, 1,
	       "Variable: ", arg_STRING);
  add_command ("gmerge",	cmd_gmerge,	1, 1, 1,
	       "Group: ", arg_GROUP);
  add_command ("gmove",		cmd_gmove,	1, 1, 1,
	       "Group: ", arg_GROUP);
  add_command ("gnew",		cmd_gnew,	1, 1, 1,
	       "Name: ", arg_STRING);
  add_command ("gnewbg",	cmd_gnewbg,	1, 1, 1,
	       "Name: ", arg_STRING);
  add_command ("gnext",		cmd_gnext,	0, 0, 0);
  add_command ("gprev",		cmd_gprev,	0, 0, 0);
  add_command ("gravity",	cmd_gravity,	1, 0, 1,
	       "Gravity: ", arg_GRAVITY);
  add_command ("groups",	cmd_groups,	0, 0, 0);
  add_command ("gselect",	cmd_gselect,	1, 1, 1,
	       "Group: ", arg_GROUP);
  add_command ("help",		cmd_help,	1, 0, 0,
	       "Keymap: ", arg_KEYMAP);
  add_command ("hsplit",	cmd_h_split,	1, 0, 0,
	       "Split: ", arg_STRING);
  add_command ("info",		cmd_info,	0, 0, 0);
  add_command ("kill",		cmd_kill,	0, 0, 0);
  add_command ("lastmsg",	cmd_lastmsg,	0, 0, 0);
  add_command ("license",	cmd_license,	0, 0, 0);
  add_command ("link",		cmd_link,	2, 1, 1,
	       "Key: ", arg_STRING,
	       "Keymap: ", arg_KEYMAP);
  add_command ("listhook",	cmd_listhook,	1, 1, 1,
	       "Hook: ", arg_HOOK);
  add_command ("meta",		cmd_meta,	0, 0, 0);
  add_command ("msgwait",	cmd_msgwait,	1, 0, 0,
	       "", arg_NUMBER);
  add_command ("newkmap",	cmd_newkmap,	1, 1, 1,
	       "Keymap: ", arg_STRING);
  add_command ("newwm",		cmd_newwm,	1, 1, 1,
	       "Switch to wm: ", arg_REST);
  add_command ("next",		cmd_next,	0, 0, 0);
  add_command ("nextscreen",	cmd_nextscreen,	0, 0, 0);
  add_command ("number",	cmd_number,	2, 1, 1,
	       "Number: ", arg_NUMBER,
	       "Number: ", arg_NUMBER);
  add_command ("only",		cmd_only,	0, 0, 0);
  add_command ("other",		cmd_other,	0, 0, 0);
  add_command ("prev",		cmd_prev,	0, 0, 0);
  add_command ("prevscreen",	cmd_prevscreen,	0, 0, 0);
  add_command ("quit",		cmd_quit,	0, 0, 0);
  add_command ("ratwarp",	cmd_ratwarp,	2, 2, 2,
	       "X: ", arg_NUMBER,
	       "Y: ", arg_NUMBER);
  add_command ("ratrelwarp",	cmd_ratrelwarp,	2, 2, 2,
	       "X: ", arg_NUMBER,
	       "Y: ", arg_NUMBER);
  add_command ("ratclick",	cmd_ratclick,	1, 0, 0,
	       "Button: ", arg_NUMBER);
  add_command ("rathold",	cmd_rathold,	2, 1, 1,
	       "State: ", arg_STRING,
	       "Button: ", arg_NUMBER);
  add_command ("readkey",	cmd_readkey,	1, 1, 1,
	       "Keymap: ", arg_KEYMAP);
  add_command ("redisplay",	cmd_redisplay,	0, 0, 0);
  add_command ("remhook",	cmd_remhook,	2, 2, 2,
	       "Hook: ", arg_HOOK,
	       "Command: ", arg_REST);
  add_command ("remove",	cmd_remove,	0, 0, 0);
  add_command ("resize",	cmd_resize,	2, 0, 2,
	       "", arg_NUMBER,
	       "", arg_NUMBER);
  add_command ("restart",	cmd_restart,	0, 0, 0);
  add_command ("rudeness",	cmd_rudeness,	1, 0, 0,
	       "Rudeness: ", arg_NUMBER);
  add_command ("select",	cmd_select,	1, 0, 1,
	       "Select window: ", arg_REST);
  add_command ("set",		cmd_set,	2, 0, 0,
	       "", arg_VARIABLE,
	       "", arg_REST);
  add_command ("setenv",	cmd_setenv,	2, 2, 2,
	       "Variable: ", arg_STRING,
	       "Value: ", arg_REST);
  add_command ("shrink",	cmd_shrink,	0, 0, 0);
  add_command ("source",	cmd_source,	1, 1, 1,
	       "File: ", arg_REST);
  add_command ("sselect",	cmd_sselect,	1, 1, 1,
	       "Screen: ", arg_NUMBER);
  add_command ("startup_message", cmd_startup_message,	1, 1, 1,
	       "Startup message: ", arg_STRING);
  add_command ("time",		cmd_time,	0, 0, 0);
  add_command ("title",		cmd_rename,	1, 1, 1,
	       "Set window's title to: ", arg_REST);
  add_command ("tmpwm",		cmd_tmpwm,	1, 1, 1,
	       "Tmp wm: ", arg_REST);
  add_command ("unalias",	cmd_unalias,	1, 1, 1,
	       "Alias: ", arg_STRING);
  add_command ("unmanage",	cmd_unmanage,	1, 1, 0,
	       "Unmanage: ", arg_REST);
  add_command ("unsetenv",	cmd_unsetenv,	1, 1, 1,
	       "Variable: ", arg_STRING);
  add_command ("verbexec",	cmd_verbexec,	1, 1, 1,
	       "/bin/sh -c ", arg_SHELLCMD);
  add_command ("version",	cmd_version,	0, 0, 0);
  add_command ("vsplit",	cmd_v_split,	1, 0, 0,
	       "Split: ", arg_STRING);
  add_command ("warp",		cmd_warp,	1, 1, 1,
	       "Warp State: ", arg_STRING);
  add_command ("windows",	cmd_windows,	1, 0, 0,
	       "", arg_REST);
  add_command ("cnext",		cmd_cnext,	0, 0, 0);
  add_command ("cother",	cmd_cother,	0, 0, 0);
  add_command ("cprev",		cmd_cprev,	0, 0, 0);
  add_command ("dedicate",	cmd_dedicate,	1, 0, 0,
	       "", arg_NUMBER);
  add_command ("describekey",	cmd_describekey, 1, 1, 1,
	       "Keymap: ", arg_KEYMAP);
  add_command ("inext",		cmd_inext,	0, 0, 0);
  add_command ("iother",	cmd_iother,	0, 0, 0);
  add_command ("iprev",		cmd_iprev,	0, 0, 0);
  add_command ("prompt",	cmd_prompt,	1, 0, 0,
	       "", arg_REST);
  add_command ("sdump",		cmd_sdump,	0, 0, 0);
  add_command ("sfdump",	cmd_sfdump,	0, 0, 0);
  add_command ("undo",		cmd_undo,	0, 0, 0);
  add_command ("putsel",	cmd_putsel,	1, 1, 1,
	       "Text: ", arg_RAW);
  add_command ("getsel",	cmd_getsel,	0, 0, 0);
  /*@end (tag required for genrpbindings) */

  /* Commands to help debug ratpoison. */
#ifdef DEBUG
#endif

  /* the following screen commands may or may not be able to be
     implemented.  See the screen documentation for what should be
     emulated with these commands */
#if 0
  add_command ("msgminwait", cmd_unimplemented, 0);
  add_command ("nethack", cmd_unimplemented, 0);
  add_command ("sleep", cmd_unimplemented, 0);
  add_command ("stuff", cmd_unimplemented, 0);
#endif

  init_set_vars();
}

typedef struct
{
  char *name;
  char *alias;
} alias_t;
  
static alias_t *alias_list;
static int alias_list_size;
static int alias_list_last;

static cmdret* frestore (char *data, rp_screen *s);
static char* fdump (rp_screen *screen);

static void 
push_frame_undo(rp_screen *screen)
{
  rp_frame_undo *cur;
  if (rp_num_frame_undos > defaults.maxundos)
    {
      /* Delete the oldest node */
      list_last (cur, &rp_frame_undos, node);
      pop_frame_undo (cur);
    }
  cur = xmalloc (sizeof(rp_frame_undo));
  cur->frames = fdump (screen);
  cur->screen = screen;
  list_add (&cur->node, &rp_frame_undos);
  rp_num_frame_undos++;		/* increment counter */
}

void
pop_frame_undo (rp_frame_undo *u)
{
  if (!u) return;
  if (u->frames) free (u->frames);
  list_del (&(u->node));
  rp_num_frame_undos--;		/* decrement counter */
}

rp_action*
find_keybinding_by_action (char *action, rp_keymap *map)
{
  int i;

  for (i=0; i<map->actions_last; i++)
    {
      if (!strcmp (map->actions[i].data, action))
	{
	  return &map->actions[i];
	}
    }

  return NULL;
}

rp_action*
find_keybinding (KeySym keysym, int state, rp_keymap *map)
{
  int i;
  for (i = 0; i < map->actions_last; i++)
    {
      if (map->actions[i].key == keysym 
	  && map->actions[i].state == state)
	return &map->actions[i];
    }
  return NULL;
}

static char *
find_command_by_keydesc (char *desc, rp_keymap *map)
{
  int i = 0;
  char *keysym_name;

  while (i < map->actions_last)
    {
      keysym_name = keysym_to_string (map->actions[i].key, map->actions[i].state);
      if (!strcmp (keysym_name, desc))
        {
          free (keysym_name);
          return map->actions[i].data;
        }
      free (keysym_name);
      i++;
    }

  return NULL;
}

static char *
resolve_command_from_keydesc (char *desc, int depth, rp_keymap *map)
{
  char *cmd, *command;

  command = find_command_by_keydesc (desc, map);
  if (!command)
    return NULL;

  /* is it a link? */
  if (strncmp (command, "link", 4) || depth > MAX_LINK_DEPTH)
    /* it is not */
    return command;

  cmd = resolve_command_from_keydesc (&command[5], depth + 1, map);
  return (cmd != NULL) ? cmd : command;
}


static void
add_keybinding (KeySym keysym, int state, char *cmd, rp_keymap *map)
{
  if (map->actions_last >= map->actions_size)
    {
      /* double the key table size */
      map->actions_size *= 2;
      map->actions = (rp_action*) xrealloc (map->actions, sizeof (rp_action) * map->actions_size);
      PRINT_DEBUG (("realloc()ed key_table %d\n", map->actions_size));
    }

  map->actions[map->actions_last].key = keysym;
  map->actions[map->actions_last].state = state;
  /* free this on shutdown, or re/unbinding */
  map->actions[map->actions_last].data = xstrdup (cmd); 

  map->actions_last++;
}

static void
replace_keybinding (rp_action *key_action, char *newcmd)
{
  if (strlen (key_action->data) < strlen (newcmd))
    key_action->data = (char*) realloc (key_action->data, strlen (newcmd) + 1);

  strcpy (key_action->data, newcmd);
}

static int
remove_keybinding (KeySym keysym, int state, rp_keymap *map)
{
  int i;
  int found = -1;

  for (i=0; i<map->actions_last; i++)
    {
      if (map->actions[i].key == keysym && map->actions[i].state == state)
	{
	  found = i;
	  break;
	}
    }

  if (found >= 0)
    {
      free (map->actions[found].data);

      memmove (&map->actions[found], &map->actions[found+1], 
	       sizeof (rp_action) * (map->actions_last - found - 1));
      map->actions_last--;
      
      return 1;
    }

  return 0;
}

rp_keymap *
keymap_new (char *name)
{
  rp_keymap *map;

  /* All keymaps must have a name. */
  if (name == NULL) 
    return NULL;

  map = xmalloc (sizeof (rp_keymap));
  map->name = xstrdup (name);
  map->actions_size = 1;
  map->actions = (rp_action*) xmalloc (sizeof (rp_action) * map->actions_size);
  map->actions_last = 0;

  return map;
}

rp_keymap *
find_keymap (char *name)
{
  rp_keymap *cur;

  list_for_each_entry (cur, &rp_keymaps, node)
    {
      if (!strcmp (name, cur->name))
	{
	  return cur;
	}
    }

  return NULL;
}

/* Search the alias table for a match. If a match is found, return its
   index into the table. Otherwise return -1. */
static int
find_alias_index (char *name)
{
  int i;

  for (i=0; i<alias_list_last; i++)
    if (!strcmp (name, alias_list[i].name))
      return i;

  return -1;
}

static void
add_alias (char *name, char *alias)
{
  int index;

  /* Are we updating an existing alias, or creating a new one? */
  index = find_alias_index (name);
  if (index >= 0)
    {
      free (alias_list[index].alias);
      alias_list[index].alias = xstrdup (alias);
    }
  else
    {
      if (alias_list_last >= alias_list_size)
	{
	  alias_list_size *= 2;
	  alias_list = xrealloc (alias_list, sizeof (alias_t) * alias_list_size);
	}

      alias_list[alias_list_last].name = xstrdup (name);
      alias_list[alias_list_last].alias = xstrdup (alias);
      alias_list_last++;
    }
}

void
initialize_default_keybindings (void)
{
  rp_keymap *map, *top;

  map = keymap_new (ROOT_KEYMAP);
  list_add (&map->node, &rp_keymaps);

  top = keymap_new (TOP_KEYMAP);
  list_add (&top->node, &rp_keymaps);

  /* Initialive the alias list. */
  alias_list_size = 5;
  alias_list_last = 0;
  alias_list = xmalloc (sizeof (alias_t) * alias_list_size);

  prefix_key.sym = KEY_PREFIX;
  prefix_key.state = MODIFIER_PREFIX;

  /* Add the prefix key to the top-level map. */
  add_keybinding (prefix_key.sym, prefix_key.state, "readkey " ROOT_KEYMAP, top);

  add_keybinding (prefix_key.sym, prefix_key.state, "other", map);
  add_keybinding (prefix_key.sym, 0, "meta", map);
  add_keybinding (XK_g, RP_CONTROL_MASK, "abort", map);
  add_keybinding (XK_0, 0, "select 0", map);
  add_keybinding (XK_1, 0, "select 1", map);
  add_keybinding (XK_2, 0, "select 2", map);
  add_keybinding (XK_3, 0, "select 3", map);
  add_keybinding (XK_4, 0, "select 4", map);
  add_keybinding (XK_5, 0, "select 5", map);
  add_keybinding (XK_6, 0, "select 6", map);
  add_keybinding (XK_7, 0, "select 7", map);
  add_keybinding (XK_8, 0, "select 8", map);
  add_keybinding (XK_9, 0, "select 9", map);
  add_keybinding (XK_minus, 0, "select -", map);
  add_keybinding (XK_A, 0, "title", map);
  add_keybinding (XK_A, RP_CONTROL_MASK, "title", map);
  add_keybinding (XK_K, 0, "kill", map);
  add_keybinding (XK_K, RP_CONTROL_MASK, "kill", map);
  add_keybinding (XK_Return, 0, "next", map);
  add_keybinding (XK_Return, RP_CONTROL_MASK,	"next", map);
  add_keybinding (XK_a, 0, "time", map);
  add_keybinding (XK_a, RP_CONTROL_MASK, "time", map);
  add_keybinding (XK_b, 0, "banish", map);
  add_keybinding (XK_b, RP_CONTROL_MASK, "banish", map);
  add_keybinding (XK_c, 0, "exec " TERM_PROG, map);
  add_keybinding (XK_c, RP_CONTROL_MASK, "exec " TERM_PROG, map);
  add_keybinding (XK_colon, 0, "colon", map);
  add_keybinding (XK_exclam, 0, "exec", map);
  add_keybinding (XK_exclam, RP_CONTROL_MASK, "colon exec " TERM_PROG " -e ", map);
  add_keybinding (XK_i, 0, "info", map);
  add_keybinding (XK_i, RP_CONTROL_MASK, "info", map);
  add_keybinding (XK_k, 0, "delete", map);
  add_keybinding (XK_k, RP_CONTROL_MASK, "delete", map);
  add_keybinding (XK_l, 0, "redisplay", map);
  add_keybinding (XK_l, RP_CONTROL_MASK, "redisplay", map);
  add_keybinding (XK_m, 0, "lastmsg", map);
  add_keybinding (XK_m, RP_CONTROL_MASK, "lastmsg", map);
  add_keybinding (XK_n, 0, "next", map);
  add_keybinding (XK_n, RP_CONTROL_MASK, "next", map);
  add_keybinding (XK_p, 0, "prev", map);
  add_keybinding (XK_p, RP_CONTROL_MASK, "prev", map);
  add_keybinding (XK_quoteright, 0, "select", map);
  add_keybinding (XK_quoteright, RP_CONTROL_MASK, "select", map);
  add_keybinding (XK_space, 0, "next", map);
  add_keybinding (XK_space, RP_CONTROL_MASK, "next", map);
  add_keybinding (XK_v, 0, "version", map);
  add_keybinding (XK_v, RP_CONTROL_MASK, "version", map);
  add_keybinding (XK_V, 0, "license", map);
  add_keybinding (XK_V, RP_CONTROL_MASK, "license", map);
  add_keybinding (XK_w, 0, "windows", map);
  add_keybinding (XK_w, RP_CONTROL_MASK, "windows", map);
  add_keybinding (XK_s, 0, "split", map);
  add_keybinding (XK_s, RP_CONTROL_MASK, "split", map);
  add_keybinding (XK_S, 0, "hsplit", map);
  add_keybinding (XK_S, RP_CONTROL_MASK, "hsplit", map);
  add_keybinding (XK_Tab, 0, "focus", map);
  add_keybinding (XK_Tab, RP_META_MASK, "focuslast", map);
  add_keybinding (XK_Left, 0, "focusleft", map);
  add_keybinding (XK_Right, 0, "focusright", map);
  add_keybinding (XK_Up, 0, "focusup", map);
  add_keybinding (XK_Down, 0, "focusdown", map);
  add_keybinding (XK_Q, 0, "only", map);
  add_keybinding (XK_R, 0, "remove", map);
  add_keybinding (XK_f, 0, "fselect", map);
  add_keybinding (XK_f, RP_CONTROL_MASK, "fselect", map);
  add_keybinding (XK_F, 0, "curframe", map);
  add_keybinding (XK_r, 0, "resize", map);
  add_keybinding (XK_r, RP_CONTROL_MASK, "resize", map);
  add_keybinding (XK_question, 0, "help " ROOT_KEYMAP, map);
  add_keybinding (XK_underscore, RP_CONTROL_MASK, "undo", map);

  add_alias ("unbind", "undefinekey " ROOT_KEYMAP);
  add_alias ("bind", "definekey " ROOT_KEYMAP);
  add_alias ("split", "vsplit");
  add_alias ("defresizeunit", "set resizeunit");
  add_alias ("defwingravity", "set wingravity");
  add_alias ("deftransgravity", "set transgravity");
  add_alias ("defmaxsizegravity", "set maxsizegravity");
  add_alias ("defbargravity", "set bargravity");
  add_alias ("deffont", "set font");
  add_alias ("defpadding", "set padding");
  add_alias ("defborder", "set border");
  add_alias ("defbarborder", "set barborder");
  add_alias ("definputwidth", "set inputwidth");
  add_alias ("defwaitcursor", "set waitcursor");
  add_alias ("defwinfmt", "set winfmt");
  add_alias ("defwinname", "set winname");
  add_alias ("deffgcolor", "set fgcolor");
  add_alias ("defbgcolor", "set bgcolor");
  add_alias ("defbarpadding", "set barpadding");
  add_alias ("defwinliststyle", "set winliststyle");
  add_alias ("defframesels", "set framesels");
  add_alias ("defmaxundos", "set maxundos");
}

void
keymap_free (rp_keymap *map)
{
  int i;

  /* Free the data in the actions. */
  for (i=0; i<map->actions_last; i++)
    {
      free (map->actions[i].data);
    }

  /* Free the map data. */
  free (map->actions);
  free (map->name);

  /* ...and the map itself. */
  free (map);
}

void
free_keymaps ()
{
  rp_keymap *cur;
  struct list_head *tmp, *iter;

  list_for_each_safe_entry (cur, iter, tmp, &rp_keymaps, node)
    {
      list_del (&cur->node);
      keymap_free (cur);
    }
}

void
free_aliases ()
{
  int i;

  /* Free the alias data. */
  for (i=0; i<alias_list_last; i++)
    {
      free (alias_list[i].name);
      free (alias_list[i].alias);
    }

  /* Free the alias list. */
  free (alias_list);
}

/* return a KeySym from a string that contains either a hex value or
   an X keysym description */
static int string_to_keysym (char *str) 
{ 
  int retval; 
  int keysym;

  retval = sscanf (str, "0x%x", &keysym);

  if (!retval || retval == EOF)
    keysym = XStringToKeysym (str);

  return keysym;
}

/* Parse a key description. 's' is, naturally, the key description. */
struct rp_key*
parse_keydesc (char *s)
{
  static struct rp_key key;
  struct rp_key *p = &key;
  char *token, *next_token, *keydesc;

  if (s == NULL) 
    return NULL;

  /* Avoid mangling s. */
  keydesc = xstrdup (s);

  p->state = 0;
  p->sym = 0;

  if (!strchr (keydesc, '-'))
    {
      /* Its got no hyphens in it, so just grab the keysym */
      p->sym = string_to_keysym (keydesc);
    }
  else
    {
      /* Its got hyphens, so parse out the modifiers and keysym */
      token = strtok (keydesc, "-");

      if (token == NULL)
	{
	  /* It was nothing but hyphens */
	  free (keydesc);
	  return NULL;
	}

      do
	{
	  next_token = strtok (NULL, "-");

	  if (next_token == NULL)
	    {
	      /* There is nothing more to parse and token contains the
		 keysym name. */
	      p->sym = string_to_keysym (token);
	    }
	  else
	    {
	      /* Which modifier is it? Only accept modifiers that are
		 present. ie don't accept a hyper modifier if the keymap
		 has no hyper key. */
	      if (!strcmp (token, "C"))
		{
		  p->state |= RP_CONTROL_MASK;
		}
	      else if (!strcmp (token, "M"))
		{
		  p->state |= RP_META_MASK;
		}
	      else if (!strcmp (token, "A"))
		{
		  p->state |= RP_ALT_MASK;
		}
	      else if (!strcmp (token, "S"))
		{
		  p->state |= RP_SHIFT_MASK;
		}
	      else if (!strcmp (token, "s"))
		{
		  p->state |= RP_SUPER_MASK;
		}
	      else if (!strcmp (token, "H"))
		{
		  p->state |= RP_HYPER_MASK;
		}
	      else
		{
		  free (keydesc);
		  return NULL;
		}
	    }

	  token = next_token;
	} while (next_token != NULL);
    }

  free (keydesc);

  if (!p->sym)
    return NULL;
  else
    return p;
}

static cmdret *
cmdret_new (char *output, int success)
{
  cmdret *ret;
  ret = xmalloc (sizeof (cmdret *));
  ret->output = output ? xstrdup (output) : NULL;
  ret->success = success;
  return ret;
}

static cmdret *
cmdret_new_printf (int success, char *fmt, ...)
{
  cmdret *ret = xmalloc (sizeof (cmdret *));
  va_list ap;

  va_start (ap, fmt);
  ret->output = xvsprintf (fmt, ap);
  ret->success = success;
  va_end (ap);

  return ret;
}

void
cmdret_free (cmdret *ret)
{
  if (ret->output)
    free (ret->output);
  free (ret);
}

/* Unmanage window */
cmdret *
cmd_unmanage (int interactive, struct cmdarg **args)
{
  if (args[0] == NULL && !interactive)
    return cmdret_new (list_unmanaged_windows(), RET_SUCCESS);

  if (args[0])
    add_unmanaged_window(ARG_STRING(0));
  else
    return cmdret_new ("unmanage: at least one argument required", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

/* Clear the unmanaged window list */
cmdret *
cmd_clrunmanaged (int interactive, struct cmdarg **args)
{
  clear_unmanaged_list();
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_undefinekey (int interactive, struct cmdarg **args)
{
  cmdret *ret = NULL;
  rp_keymap *map;
  struct rp_key *key;

  map = ARG (0, keymap);
  key = ARG (1, key);

  /* If we're updating the top level map, we'll need to update the
     keys grabbed. */
  if (map == find_keymap (TOP_KEYMAP))
    ungrab_keys_all_wins ();

  /* If no comand is specified, then unbind the key. */
  if (!remove_keybinding (key->sym, key->state, map))
    ret = cmdret_new_printf (RET_FAILURE, "undefinekey: key '%s' is not bound", ARG_STRING(1));

  /* Update the grabbed keys. */
  if (map == find_keymap (TOP_KEYMAP))
    grab_keys_all_wins ();
  XSync (dpy, False);

  if (ret)
    return ret;
    else
      return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_definekey (int interactive, struct cmdarg **args)
{
  cmdret *ret = NULL;
  rp_keymap *map;
  struct rp_key *key;
  char *cmd;
  rp_action *key_action;

  map = ARG(0,keymap);
  key = ARG(1,key);
  cmd = ARG_STRING(2);

  /* If we're updating the top level map, we'll need to update the
     keys grabbed. */
  if (map == find_keymap (TOP_KEYMAP))
    ungrab_keys_all_wins ();

  if ((key_action = find_keybinding (key->sym, key->state, map)))
    replace_keybinding (key_action, ARG_STRING(2));
  else
    add_keybinding (key->sym, key->state, ARG_STRING(2), map);

  /* Update the grabbed keys. */
  if (map == find_keymap (TOP_KEYMAP))
    grab_keys_all_wins ();
  XSync (dpy, False);

  if (ret)
    return ret;
  else
    return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_unimplemented (int interactive, struct cmdarg **args)
{
  return cmdret_new ("FIXME:  unimplemented command", RET_FAILURE);
}

cmdret *
cmd_source (int interactive, struct cmdarg **args)
{
  FILE *fileptr;

  if ((fileptr = fopen (ARG_STRING(0), "r")) == NULL)
    return cmdret_new_printf (RET_FAILURE, "source: %s : %s", ARG_STRING(0), strerror(errno));
  else
    {
      set_close_on_exec (fileptr);
      read_rc_file (fileptr);
      fclose (fileptr);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_meta (int interactive, struct cmdarg **args)
{
  XEvent ev1, ev;
  ev = rp_current_event;

  if (current_window() == NULL) 
    return cmdret_new (NULL, RET_FAILURE);

  ev1.xkey.type = KeyPress;
  ev1.xkey.display = dpy;
  ev1.xkey.window = current_window()->w;
  ev1.xkey.state = rp_mask_to_x11_mask (prefix_key.state);
  ev1.xkey.keycode = XKeysymToKeycode (dpy, prefix_key.sym);

  XSendEvent (dpy, current_window()->w, False, KeyPressMask, &ev1);

  /*   XTestFakeKeyEvent (dpy, XKeysymToKeycode (dpy, 't'), True, 0); */

  XSync (dpy, False);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_prev (int interactive, struct cmdarg **args)
{
  rp_window *cur, *win;
  cur = current_window();
  win = group_prev_window (rp_current_group, cur);

  if (win)
    set_active_window (win);
  else if (cur)
    return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
  else
    return cmdret_new (MESSAGE_NO_MANAGED_WINDOWS, RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_prev_frame (int interactive, struct cmdarg **args)
{
  rp_frame *frame;

  frame = find_frame_prev (current_frame());
  if (!frame)
    return cmdret_new (MESSAGE_NO_OTHER_FRAME, RET_FAILURE);
  else
    set_active_frame (frame);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_next (int interactive, struct cmdarg **args)
{
  rp_window *cur, *win;
  cur = current_window();
  win = group_next_window (rp_current_group, cur);

  if (win)
    set_active_window (win);
  else if (cur)
    return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
  else
    return cmdret_new (MESSAGE_NO_MANAGED_WINDOWS, RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_next_frame (int interactive, struct cmdarg **args)
{
  rp_frame *frame;

  frame = find_frame_next (current_frame());
  if (!frame)
    return cmdret_new (MESSAGE_NO_OTHER_FRAME, RET_FAILURE);
  else
    set_active_frame (frame);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_other (int interactive, struct cmdarg **args)
{
  rp_window *w;

/*   w = find_window_other (); */
  w = group_last_window (rp_current_group, current_screen());

  if (!w)
    return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
  else
    set_active_window_force (w);

  return cmdret_new (NULL, RET_SUCCESS);
}

static int
string_to_window_number (char *str)
{
  int i;
  char *s;

  for (i = 0, s = str; *s; s++)
    {
      if (*s < '0' || *s > '9')
        break;
      i = i * 10 + (*s - '0');
    }

  return *s ? -1 : i;
}

struct list_head *
null_completions ()
{
;
}

struct list_head *
trivial_completions (char* str)
{
  struct list_head *list;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);

  return list;
}

struct list_head *
keymap_completions (char* str)
{
  rp_keymap *cur;
  struct list_head *list;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);

  list_for_each_entry (cur, &rp_keymaps, node)
    {
      struct sbuf *name;

      name = sbuf_new (0);
      sbuf_copy (name, cur->name);
      list_add_tail (&name->node, list);
    }

  return list;
}

struct list_head *
window_completions (char* str)
{
  rp_window_elem *cur;
  struct list_head *list;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);

  /* Gather the names of all the windows. */
  list_for_each_entry (cur, &rp_current_group->mapped_windows, node)
    {
      struct sbuf *name;

      name = sbuf_new (0);
      sbuf_copy (name, window_name (cur->win));
      list_add_tail (&name->node, list);
    }

  return list;
}

/* switch to window number or name */
cmdret *
cmd_select (int interactive, struct cmdarg **args)
{
  cmdret *ret = NULL;
  char *str;
  int n;

  /* FIXME: This is manually done because of the kinds of things
     select accepts. */
  if (args[0] == NULL)
    str = get_input (MESSAGE_PROMPT_SWITCH_TO_WINDOW, window_completions);
  else
    str = xstrdup (ARG_STRING(0));

  /* User aborted. */
  if (str == NULL)
    return cmdret_new (NULL, RET_FAILURE);

  /* Only search if the string contains something to search for. */
  if (strlen (str) > 0)
    {
      if (strlen (str) == 1 && str[0] == '-')
	{
	  blank_frame (current_frame());
	}
      /* try by number */
      else if ((n = string_to_window_number (str)) >= 0)
	{
	  rp_window_elem *elem = group_find_window_by_number (rp_current_group, n);

	  if (elem)
	    goto_window (elem->win);
	  else
	    /* show the window list as feedback */
	    show_bar (current_screen ());
	}
      else
	/* try by name */
	{
	  rp_window *win = find_window_name (str);

	  if (win)
	    goto_window (win);
	  else
	    ret = cmdret_new_printf (RET_FAILURE, "select: unknown window '%s'", str);
	}
    }

  free (str);

  if (ret)
    return ret;
  else
    return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_rename (int interactive, struct cmdarg **args)
{
  if (current_window() == NULL) 
    return cmdret_new (NULL, RET_FAILURE);

  free (current_window()->user_name);
  current_window()->user_name = xstrdup (ARG_STRING(0));
  current_window()->named = 1;
  
  /* Update the program bar. */
  update_window_names (current_screen());

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_delete (int interactive, struct cmdarg **args)
{
  XEvent ev;
  int status;

  if (current_window() == NULL)
    return cmdret_new (NULL, RET_FAILURE);

  ev.xclient.type = ClientMessage;
  ev.xclient.window = current_window()->w;
  ev.xclient.message_type = wm_protocols;
  ev.xclient.format = 32;
  ev.xclient.data.l[0] = wm_delete;
  ev.xclient.data.l[1] = CurrentTime;

  status = XSendEvent(dpy, current_window()->w, False, 0, &ev);
  if (status == 0)
    PRINT_DEBUG (("Delete window failed\n"));

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_kill (int interactive, struct cmdarg **args)
{
  if (current_window() == NULL)
    return cmdret_new (NULL, RET_FAILURE);

  XKillClient(dpy, current_window()->w);

  return cmdret_new (NULL, RET_FAILURE);
}

cmdret *
cmd_version (int interactive, struct cmdarg **args)
{
  return cmdret_new (PACKAGE " " VERSION " (built " __DATE__ " " __TIME__ ")", RET_SUCCESS);
}

static char *
frame_selector (int n)
{
  if (n < strlen (defaults.frame_selectors))
    {
      return xsprintf (" %c ", defaults.frame_selectors[n]);
    }
  else
    {
      return xsprintf (" %d ", n);
    }
}

/* Return true if ch is nth frame selector. */
static int
frame_selector_match (char ch)
{
  int i;

  /* Is it in the frame selector string? */
  for (i=0; i<strlen (defaults.frame_selectors); i++)
    {
      if (ch == defaults.frame_selectors[i])
	return i;
    }

  /* Maybe it's a number less than 9 and the frame selector doesn't
     define that many selectors. */
  if (ch >= '0' && ch <= '9'
      && ch - '0' >= strlen (defaults.frame_selectors))
    {
      return ch - '0';
    }

  return -1;
}

static cmdret *
read_string (struct argspec *spec, struct sbuf *s, completion_fn fn,  struct cmdarg **arg)
{
  char *input;

  if (s)
    input = xstrdup (sbuf_get(s));
  else
    input = get_input (spec->prompt, fn);

  if (input)
    {      
      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = spec->type;
      (*arg)->string = input;
      return NULL;
    }

  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
read_keymap (struct argspec *spec, struct sbuf *s, struct cmdarg **arg)
{
  char *input;
  if (s)
    input = xstrdup (sbuf_get (s));
  else
    input = get_input (spec->prompt, keymap_completions);

  if (input)
    {
      rp_keymap *map;
      map = find_keymap (input);
      if (map == NULL)
	return cmdret_new_printf (RET_FAILURE, "unknown keymap '%s'", input);
      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = spec->type;
      (*arg)->arg.keymap = map;
      (*arg)->string = input;
      return NULL;
    }

  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
read_keydesc (struct argspec *spec, struct sbuf *s, struct cmdarg **arg)
{
  char *input;
  if (s)
    input = xstrdup (sbuf_get (s));
  else
    input = get_input (spec->prompt, trivial_completions);

  if (input)
    {
      struct rp_key *key;
      key = parse_keydesc (input);
      if (key == NULL)
	return cmdret_new_printf (RET_FAILURE, "Bad key description '%s'", input);
      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = spec->type;
      (*arg)->arg.key = key;
      (*arg)->string = input;
      return NULL;
    }

  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

struct list_head *
group_completions (char *str)
{
  struct list_head *list;
  rp_group *cur;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);

  /* Grab all the group names. */
  list_for_each_entry (cur, &rp_groups, node)
    {
      struct sbuf *s;

      s = sbuf_new (0);
      /* A group may not have a name, so if it doesn't, use it's
	 number. */
      if (cur->name)
	{
	  sbuf_copy (s, cur->name);
	}
      else
	{
	  sbuf_printf (s, "%d", cur->number);
	}

      list_add_tail (&s->node, list);
    }

  return list;
}

struct list_head *
colon_completions (char* str)
{
  int i;
  struct user_command *uc;
  struct sbuf *s;
  struct list_head *list;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);

  /* Put all the aliases in our list. */
  for(i=0; i<alias_list_last; ++i)
    {
      s = sbuf_new (0);
      sbuf_copy (s, alias_list[i].name);
      /* The space is so when the user completes a space is
	 conveniently inserted after the command. */
      sbuf_concat (s, " ");
      list_add_tail (&s->node, list);
    }

  /* Put all the commands in our list. */
  list_for_each_entry (uc, &user_commands, node)
    {
      s = sbuf_new (0);
      sbuf_copy (s, uc->name);
      /* The space is so when the user completes a space is
	 conveniently inserted after the command. */
      sbuf_concat (s, " ");
      list_add_tail (&s->node, list);
    }

  return list;
}

static cmdret *
read_command (struct argspec *spec, struct sbuf *s, struct cmdarg **arg)
{
  return read_string (spec, s, colon_completions, arg);
}

struct list_head *
exec_completions (char *str)
{
  size_t n = 256;
  char *partial;
  struct sbuf *line;
  FILE *file;
  struct list_head *head;
  char *completion_string;

  /* Initialize our list. */
  head = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (head);
	
  /* FIXME: A Bash dependancy?? */
  completion_string = xsprintf("bash -c \"compgen -ac %s|sort\"", str);
  file = popen (completion_string, "r");
  free (completion_string);
  if (!file)
    {
      PRINT_ERROR (("popen failed\n"));
      return head;
    }

  partial = (char*)xmalloc (n);

  /* Read data from the file, split it into lines and store it in a
     list. */
  line = sbuf_new (0);
  while (fgets (partial, n, file) != NULL)
    {
      /* Read a chunk from the file into our line accumulator. */
      sbuf_concat (line, partial);

      if (feof(file) || (*(sbuf_get (line) + strlen(sbuf_get (line)) - 1) == '\n'))
	{
	  char *s;
	  struct sbuf *elem;

	  s = sbuf_get (line);

	  /* Frob the newline into */
	  if (*(s + strlen(s) - 1) == '\n')
	    *(s + strlen(s) - 1) = '\0';
	      
	  /* Add our line to the list. */
	  elem = sbuf_new (0);
	  sbuf_copy (elem, s);
	  /* The space is so when the user completes a space is
	     conveniently inserted after the command. */
	  sbuf_concat (elem, " ");
	  list_add_tail (&elem->node, head);

	  sbuf_clear (line);
	}
    }

  free (partial);
  pclose (file);

  return head;
}

static cmdret *
read_shellcmd (struct argspec *spec, struct sbuf *s, struct cmdarg **arg)
{
  return read_string (spec, s, exec_completions, arg);
}

/* Return NULL on abort/failure. */
static cmdret *
read_frame (struct argspec *spec, struct sbuf *s,  struct cmdarg **arg)
{
  rp_frame *frame;
  int fnum = -1;
  KeySym c;
  char keysym_buf[513];
  int keysym_bufsize = sizeof (keysym_buf);
  unsigned int mod;
  Window *wins;
  int i, j;
  rp_frame *cur;
  int frames;

  if (s == NULL)
    {
      frames = 0;
      for (j=0; j<num_screens; j++)
	frames += num_frames(&screens[j]);

      wins = xmalloc (sizeof (Window) * frames);

      /* Loop through each frame and display its number in it's top
	 left corner. */
      i = 0;
      for (j=0; j<num_screens; j++)
	{
	  XSetWindowAttributes attr;
	  rp_screen *s = &screens[j];
      
	  /* Set up the window attributes to be used in the loop. */
	  attr.border_pixel = s->fg_color;
	  attr.background_pixel = s->bg_color;
	  attr.override_redirect = True;

	  list_for_each_entry (cur, &s->frames, node)
	    {
	      int width, height;
	      char *num;

	      /* Create the string to be displayed in the window and
		 determine the height and width of the window. */
	      /* 	      num = xsprintf (" %d ", cur->number); */
	      num = frame_selector (cur->number);
	      width = defaults.bar_x_padding * 2 + XTextWidth (defaults.font, num, strlen (num));
	      height = (FONT_HEIGHT (defaults.font) + defaults.bar_y_padding * 2);

	      /* Create and map the window. */
	      wins[i] = XCreateWindow (dpy, s->root, s->left + cur->x, s->top + cur->y, width, height, 1, 
				       CopyFromParent, CopyFromParent, CopyFromParent,
				       CWOverrideRedirect | CWBorderPixel | CWBackPixel,
				       &attr);
	      XMapWindow (dpy, wins[i]);
	      XClearWindow (dpy, wins[i]);

	      /* Display the frame's number inside the window. */
	      XDrawString (dpy, wins[i], s->normal_gc, 
			   defaults.bar_x_padding, 
			   defaults.bar_y_padding + defaults.font->max_bounds.ascent,
			   num, strlen (num));

	      free (num);
	      i++;
	    }
	}
      XSync (dpy, False);

      /* Read a key. */
      XGrabKeyboard (dpy, current_screen()->key_window, False, GrabModeSync, GrabModeAsync, CurrentTime);
      read_key (&c, &mod, keysym_buf, keysym_bufsize);
      XUngrabKeyboard (dpy, CurrentTime);

      /* Destroy our number windows and free the array. */
      for (i=0; i<frames; i++)
	XDestroyWindow (dpy, wins[i]);

      free (wins);

      /* FIXME: We only handle one character long keysym names. */
      if (strlen (keysym_buf) == 1)
	{
	  fnum = frame_selector_match (keysym_buf[0]);
	  if (fnum == -1)
	    goto frame_fail;
	}
      else
	{
	  goto frame_fail;
	}
    }
  else
    {
      fnum = strtol (sbuf_get (s), NULL, 10);
    }
  /* Now that we have a frame number to go to, let's try to jump to
     it. */
  frame = find_frame_number (fnum);
  if (frame)
    {
      /* We have to return a string, because commands get lists of
	 strings. Sucky, yes. The command is simply going to parse it
	 back into an rp_frame. */
      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = arg_FRAME;
      (*arg)->string = NULL;
      (*arg)->arg.frame = frame;
      return NULL;
    }


 frame_fail:
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
read_window (struct argspec *spec, struct sbuf *s, struct cmdarg **arg)
{
  rp_window *win = NULL;
  char *name;
  int n;

  if (s)
    name = xstrdup (sbuf_get (s));
  else
    name = get_input (spec->prompt, window_completions);

  if (name)
    {
      /* try by number */
      if ((n = string_to_window_number (name)) >= 0)
	{
	  rp_window_elem *elem = group_find_window_by_number (rp_current_group, n);
	  if (elem)
	    win = elem->win;
	}
      else
	/* try by name */
	{
	  win = find_window_name (name);
	}
  
      if (win)
	{
	  *arg = xmalloc (sizeof(struct cmdarg));
	  (*arg)->type = arg_WINDOW;
	  (*arg)->arg.win = win;
	  (*arg)->string = name;
	  return NULL;
	}
      else
	{
	  free (name);
	  *arg = NULL;
	  return cmdret_new (NULL, RET_SUCCESS);
	}
    }
  
  /* user abort. */
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static int
parse_wingravity (char *data)
{
  int ret = -1;

  if (!strcasecmp (data, "northwest") || !strcasecmp (data, "nw") || !strcmp (data, "7"))
    ret = NorthWestGravity;
  if (!strcasecmp (data, "north") || !strcasecmp (data, "n") || !strcmp (data, "8"))
    ret = NorthGravity;
  if (!strcasecmp (data, "northeast") || !strcasecmp (data, "ne") || !strcmp (data, "9"))
    ret = NorthEastGravity;
  if (!strcasecmp (data, "west") || !strcasecmp (data, "w") || !strcmp (data, "4"))
    ret = WestGravity;
  if (!strcasecmp (data, "center") || !strcasecmp (data, "c") || !strcmp (data, "5"))
    ret = CenterGravity;
  if (!strcasecmp (data, "east") || !strcasecmp (data, "e") || !strcmp (data, "6"))
    ret = EastGravity;
  if (!strcasecmp (data, "southwest") || !strcasecmp (data, "sw") || !strcmp (data, "1"))
    ret = SouthWestGravity;
  if (!strcasecmp (data, "south") || !strcasecmp (data, "s") || !strcmp (data, "2"))
    ret = SouthGravity;
  if (!strcasecmp (data, "southeast") || !strcasecmp (data, "se") || !strcmp (data, "3"))
    ret = SouthEastGravity;

  return ret;
}

static cmdret *
read_gravity (struct argspec *spec, struct sbuf *s,  struct cmdarg **arg)
{
  char *input;

  if (s)
    input = xstrdup (sbuf_get(s));
  else
    input = get_input (spec->prompt , trivial_completions);

  if (input)
    {
      int g = parse_wingravity (input);
      if (g == -1)
	{
	  cmdret *ret = cmdret_new_printf (RET_FAILURE, "bad gravity '%s'", input);
	  free (input);
	  return ret;
	}
      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = arg_GRAVITY;
      (*arg)->arg.gravity = g;
      (*arg)->string = input;
      return NULL;
    }
  
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Given a string, find a matching group. First check if the string is
   a number, then check if it's the name of a group. */
static rp_group *
find_group (char *str)
{
  rp_group *group;
  int n;

  /* Check if the user typed a group number. */
  n = string_to_window_number (str);
  if (n >= 0)
    {
      group = groups_find_group_by_number (n);
      if (group)
	return group;
    }

  group = groups_find_group_by_name (str);
  return group;
}

static cmdret *
read_group (struct argspec *spec, struct sbuf *s,  struct cmdarg **arg)
{
  char *input;

  if (s)
    input = xstrdup (sbuf_get(s));
  else
    input = get_input (spec->prompt , group_completions);

  if (input)
    {
      rp_group *g = find_group (input);
      
      if (g)
	{
	  *arg = xmalloc (sizeof(struct cmdarg));
	  (*arg)->type = arg_GROUP;
	  (*arg)->arg.group = g;
	  (*arg)->string = input;
	  return NULL;
	}
      else
	{
	  cmdret *ret = cmdret_new_printf (RET_FAILURE, "unknown group '%s'", input);
	  free (input);
	  return ret;
	}
    }
  
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

struct list_head *
hook_completions (char* str)
{
  struct list_head *list;
  struct rp_hook_db_entry *entry;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);
 
  for (entry = rp_hook_db; entry->name; entry++)
    {
      struct sbuf *hookname;

      hookname = sbuf_new(0);
      sbuf_copy (hookname, entry->name);
      list_add_tail (&hookname->node, list);
    }
  
  return list;
}

static cmdret *
read_hook (struct argspec *spec, struct sbuf *s,  struct cmdarg **arg)
{
  char *input;

  if (s)
    input = xstrdup (sbuf_get(s));
  else
    input = get_input (spec->prompt , hook_completions);

  if (input)
    {
      struct list_head *hook = hook_lookup (input);
      
      if (hook)
	{
	  *arg = xmalloc (sizeof(struct cmdarg));
	  (*arg)->type = arg_HOOK;
	  (*arg)->arg.hook = hook;
	  (*arg)->string = input;
	  return NULL;
	}
      else
	{
	  cmdret *ret = cmdret_new_printf (RET_FAILURE, "unknown hook '%s'", input);
	  free (input);
	  return ret;
	}
    }
  
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static struct set_var *
find_variable (char *str)
{
  struct set_var *cur;
  list_for_each_entry (cur, &set_vars, node)
    {
      if (!strcmp (str, cur->var))
	return cur;
    }
  return NULL;
}

struct list_head *
var_completions (char *str)
{
  struct list_head *list;
  struct set_var *cur;

  /* Initialize our list. */
  list = xmalloc (sizeof (struct list_head));
  INIT_LIST_HEAD (list);

  /* Grab all the group names. */
  list_for_each_entry (cur, &set_vars, node)
    {
      struct sbuf *s;
      s = sbuf_new (0);
      sbuf_copy (s, cur->var);
      list_add_tail (&s->node, list);
    }

  return list;
}

static cmdret *
read_variable (struct argspec *spec, struct sbuf *s,  struct cmdarg **arg)
{
  char *input;

  if (s)
    input = xstrdup (sbuf_get(s));
  else
    input = get_input (spec->prompt , var_completions);

  if (input)
    {
      struct set_var *var = find_variable (input);
      if (var == NULL)
	{
	  cmdret *ret = cmdret_new_printf (RET_FAILURE, "unknown variable '%s'", input);
	  free (input);
	  return ret;
	}

      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = arg_VARIABLE;
      (*arg)->arg.variable = var;
      (*arg)->string = input;
      return NULL;
    }
  
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
read_number (struct argspec *spec, struct sbuf *s,  struct cmdarg **arg)
{
  char *input;

  if (s)
    input = xstrdup (sbuf_get(s));
  else
    input = get_input (spec->prompt , trivial_completions);

  if (input)
    {
      *arg = xmalloc (sizeof(struct cmdarg));
      (*arg)->type = arg_NUMBER;
      (*arg)->arg.number = strtol (input, NULL, 10);
      (*arg)->string = input;
      return NULL;
    }
  
  *arg = NULL;
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
read_arg (struct argspec *spec, struct sbuf *s, struct cmdarg **arg)
{
  cmdret *ret = NULL;

  switch (spec->type)
    {
    case arg_STRING:
    case arg_REST:
    case arg_RAW:
      ret = read_string (spec, s, trivial_completions, arg);
      break;
    case arg_KEYMAP:
      ret = read_keymap (spec, s, arg);
      break;
    case arg_KEY:
      ret = read_keydesc (spec, s, arg);
      break;
    case arg_NUMBER:
      ret = read_number (spec, s, arg);
      break;
    case arg_GRAVITY:
      ret = read_gravity (spec, s, arg);
      break;
    case arg_COMMAND:
      ret = read_command (spec, s, arg);
      break;
    case arg_SHELLCMD:
      ret = read_shellcmd (spec, s, arg);
      break;
    case arg_WINDOW:
      ret = read_window (spec, s, arg);
      break;
    case arg_FRAME:
      ret = read_frame (spec, s, arg);
      break;
    case arg_GROUP:
      ret = read_group (spec, s, arg);
      break;
    case arg_HOOK:
      ret = read_hook (spec, s, arg);
      break;
    case arg_VARIABLE:
      ret = read_variable (spec, s, arg);
      break;
    }

  return ret;
}

/* Return -1 on failure. Return the number of args on success. */
static cmdret *
parsed_input_to_args (int num_args, struct argspec *argspec, struct list_head *list,
		      struct list_head *args, int *parsed_args)
{
  struct sbuf *s;
  struct cmdarg *arg;
  cmdret *ret;

  PRINT_DEBUG (("list len: %d\n", list_size (list)));

  *parsed_args = 0;

  /* Convert the existing entries to cmdarg's. */
  list_for_each_entry (s, list, node)
    {
      if (*parsed_args >= num_args) break;
      ret = read_arg (&argspec[*parsed_args], s, &arg);
      /* If there was an error, then abort. */
      if (ret)
	return ret;

      list_add_tail (&arg->node, args);
      (*parsed_args)++;
    }

  return NULL;
}

/* Prompt the user for missing arguments. Returns non-zero on
   failure. 0 on success. */
static cmdret *
fill_in_missing_args (struct user_command *cmd, struct list_head *list, struct list_head *args)
{
  cmdret *ret;
  struct cmdarg *arg;
  int i = 0;

  ret = parsed_input_to_args (cmd->num_args, cmd->args, list, args, &i);
  if (ret)
    return ret;

  /* Fill in the rest of the required arguments. */
  for(; i < cmd->i_required_args; i++)
    {
      ret = read_arg (&cmd->args[i], NULL, &arg);
      if (ret)
	return ret;
      list_add_tail (&arg->node, args);
    }

  return NULL;
}

/* Stick a list of sbuf's in list. if nargs >= 0 then only parse nargs
   arguments and and the rest of the string to the list. Return 0 on
   success. non-zero on failure. When raw is true, then when we hit
   nargs, we should keep any whitespace at the beginning. When false,
   gobble the whitespace. */
static cmdret *
parse_args (char *str, struct list_head *list, int nargs, int raw)
{
  cmdret *ret = NULL;
  char *i;
  char *tmp;
  int len = 0;
  int str_escape = 0;
  int in_str = 0;
  int gobble = 0;
  int parsed_args = 0;

  if (str == NULL)
    return NULL;

  tmp = malloc (strlen(str) + 1);

  for (i=str; *i; i++)
    {
      /* Have we hit the arg limit? */
      if (nargs >= 0 && parsed_args >= nargs)
	{
	  struct sbuf *s = sbuf_new(0);
	  if (!raw)
	    while (*i && *i == ' ') i++;
	  if (*i)
	    {
	      sbuf_concat(s, i);
	      list_add_tail (&s->node, list);
	    }
	  len = 0;
	  break;
	}

      /* Escaped characters always get added. */
      if (str_escape)
	{
	  tmp[len] = *i;
	  len++;
	  str_escape = 0;
	}
      else if (*i == '\\')
	{
	  str_escape = 1;
	}
      else if (*i == '"')
	{
	  if (in_str)
	    {
	      /* End the arg. */
	      struct sbuf *s = sbuf_new(0);
	      sbuf_nconcat(s, tmp, len);
	      list_add_tail (&s->node, list);
	      len = 0;
	      gobble = 1;
	      in_str = 0;
	      parsed_args++;
	    }
	  else if (len == 0)
	    {
	      /* A string open can only start at the beginning of an
		 argument. */
	      in_str = 1;
	    }
	  else
	    {
	      ret = cmdret_new_printf (RET_FAILURE, "parse error in '%s'", str);
	      break;
	    }
	}
      else if (*i == ' ' && !in_str)
	{
	  /* End the current arg, and start a new one. */
	  struct sbuf *s = sbuf_new(0);
	  sbuf_nconcat(s, tmp, len);
	  list_add_tail (&s->node, list);
	  len = 0;
	  gobble = 1;
	  parsed_args++;
	}
      else
	{
	  /* Add the character to the argument. */
	  tmp[len] = *i;
	  len++;
	}

      /* Should we eat the whitespace? */
      if (gobble)
	{
	  while (*i && *i == ' ') i++;
	  /* Did we go too far? */
	  if (*i && *i != ' ') i--;
	  gobble = 0;
	}
    }
  /* Add the remaining text in tmp. */
  if (ret == NULL && len)
    {
      struct sbuf *s = sbuf_new(0);
      sbuf_nconcat(s, tmp, len);
      list_add_tail (&s->node, list);
    }

  /* Free our memory and return. */
  free (tmp);
  return ret;
}

/* Convert the list to an array, for easier access in commands. */
static struct cmdarg **
arg_array (struct list_head *head)
{
  int i = 0;
  struct cmdarg **args, *cur;

  args = (struct cmdarg **)xmalloc (sizeof (struct cmdarg *) * (list_size (head) + 1));
  list_for_each_entry (cur, head, node)
    {
      args[i] = cur;
      i++;
    }

  /* NULL terminate the array. */
  args[list_size (head)] = NULL;
  return args;
}

static void
arg_free (struct cmdarg *arg)
{
  if (arg)
    {
      /* read_frame doesn't fill in string. */
      if (arg->string)
	free (arg->string);
      switch (arg->type)
	{
	case arg_REST:
	case arg_STRING:
	case arg_NUMBER:
	case arg_FRAME:
	case arg_WINDOW:
	  /* Do nothing */
	  break;
	}
      free (arg);
    }
}

cmdret *
command (int interactive, char *data)
{
  /* This static counter is used to exit from recursive alias calls. */
  static int alias_recursive_depth = 0;
  cmdret *result = NULL;
  char *cmd, *rest;
  char *input;
  user_command *uc;
  int i;
  
  if (data == NULL)
    return cmdret_new (NULL, RET_FAILURE);

  /* get a writable copy for strtok() */
  input = xstrdup (data);

  cmd = strtok (input, " ");

  if (cmd == NULL)
    goto done;

  rest = strtok (NULL, "\0");

  PRINT_DEBUG (("cmd==%s rest==%s\n", cmd, rest));

  /* Look for it in the aliases, first. */
  for (i=0; i<alias_list_last; i++)
    {
      if (!strcmp (cmd, alias_list[i].name))
	{
	  struct sbuf *s;

	  /* Append any arguments onto the end of the alias' command. */
	  s = sbuf_new (0);
	  sbuf_concat (s, alias_list[i].alias);
	  if (rest != NULL)
	    sbuf_printf_concat (s, " %s", rest);

	  alias_recursive_depth++;
	  if (alias_recursive_depth >= MAX_ALIAS_RECURSIVE_DEPTH)
	    result = cmdret_new ("command: alias recursion has exceeded maximum depth", RET_FAILURE);
	  else
	    result = command (interactive, sbuf_get (s));
	  alias_recursive_depth--;

	  sbuf_free (s);
	  goto done;
	}
    }

  /* If it wasn't an alias, maybe its a command. */
  list_for_each_entry (uc, &user_commands, node)
    {
      if (!strcmp (cmd, uc->name))
	{
	  struct sbuf *scur;
	  struct cmdarg *acur;
	  struct list_head *iter, *tmp;
	  struct list_head head, args;
	  int i, nargs = -1;

	  INIT_LIST_HEAD (&args);
	  INIT_LIST_HEAD (&head);

	  /* We need to tell parse_args about arg_REST and arg_SHELLCMD. */
	  for (i=0; i<uc->num_args; i++)
	    if (uc->args[i].type == arg_REST
		|| uc->args[i].type == arg_SHELLCMD
		|| uc->args[i].type == arg_RAW)
	      {
		nargs = i;
		break;
	      }

	  /* Parse the arguments and call the function. */
	  result = parse_args (rest, &head, nargs, uc->args[nargs].type == arg_RAW);
	  if (result)
	    goto free_lists;
	  
	  /* Interactive commands prompt the user for missing args. */
	  if (interactive)
	    result = fill_in_missing_args (uc, &head, &args);
	  else
	    {
	      int parsed_args;
	      result = parsed_input_to_args (uc->num_args, uc->args, &head, &args, &parsed_args);
	    }

	  if (result == NULL)
	    {
	      if ((interactive && list_size (&args) < uc->i_required_args)
		  || (!interactive && list_size (&args) < uc->ni_required_args))
		{
		  result = cmdret_new ("not enough arguments.", RET_FAILURE);
		  goto free_lists;
		}
	      else if (list_size (&head) > uc->num_args)
		{
		  result = cmdret_new ("too many arguments.", RET_FAILURE);
		  goto free_lists;
		}
	      else
		{
		  struct cmdarg **cmdargs = arg_array (&args);
		  result = uc->func (interactive, cmdargs);
		  free (cmdargs);
		}
	    }

	free_lists:
	  /* Free the parsed strings */
	  list_for_each_safe_entry (scur, iter, tmp, &head, node)
	    sbuf_free(scur);
	  /* Free the args */
	  list_for_each_safe_entry (acur, iter, tmp, &args, node)
	    arg_free (acur);

	  goto done;
	}
    }

  result = cmdret_new_printf (RET_FAILURE, MESSAGE_UNKNOWN_COMMAND, cmd);

 done:
  free (input);
  return result;
}

cmdret *
cmd_colon (int interactive, struct cmdarg **args)
{
  cmdret *result;
  char *input;

  if (args[0] == NULL)
    input = get_input (MESSAGE_PROMPT_COMMAND, colon_completions);
  else
    input = get_more_input (MESSAGE_PROMPT_COMMAND, ARG_STRING(0), colon_completions);

  /* User aborted. */
  if (input == NULL)
    return cmdret_new (NULL, RET_FAILURE);

  result = command (1, input);
  free (input);
  return result;
}

cmdret *
cmd_exec (int interactive, struct cmdarg **args)
{
  spawn (ARG_STRING(0));
  return cmdret_new (NULL, RET_SUCCESS);
}

int
spawn(char *cmd)
{
  char *tmp;
  rp_child_info *child;
  int pid;

  pid = fork();
  if (pid == 0) 
    {
      /* Some process setup to make sure the spawned process runs
	 in its own session. */
      putenv(current_screen()->display_string);
#ifdef HAVE_SETSID
      setsid();
#endif
#if defined (HAVE_SETPGID)
      setpgid (0, 0);
#elif defined (HAVE_SETPGRP)
      setpgrp (0, 0);
#endif
      /* Prepend with exec to avoid excess /bin/sh's. */
      tmp = xsprintf ("exec %s", cmd);
      execl("/bin/sh", "sh", "-c", tmp, 0);
      _exit(EXIT_FAILURE);
    }

/*   wait((int *) 0); */
  PRINT_DEBUG (("spawned %s\n", cmd));

  /* Add this child process to our list. */
  child = malloc (sizeof (rp_child_info));
  child->cmd = strdup (cmd);
  child->pid = pid;
  child->terminated = 0;

  list_add (&child->node, &rp_children);

  return pid;
}

/* Switch to a different Window Manager. Thanks to 
"Chr. v. Stuckrad" <stucki@math.fu-berlin.de> for the patch. */
cmdret *
cmd_newwm(int interactive, struct cmdarg **args)
{
  /* in the event loop, this will switch WMs. */
  rp_exec_newwm = xstrdup (ARG_STRING(0));

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_quit(int interactive, struct cmdarg **args)
{
  kill_signalled = 1;
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Show the current time on the bar. Thanks to Martin Samuelsson
   <cosis@lysator.liu.se> for the patch. Thanks to Jonathan Walther
   <krooger@debian.org> for making it pretty. */
cmdret *
cmd_time (int interactive, struct cmdarg **args)
{
  char *msg, *tmp;
  time_t timep;
  cmdret *ret;

  timep = time(NULL);
  tmp = ctime(&timep);
  msg = xmalloc (strlen (tmp));
  strncpy(msg, tmp, strlen (tmp) - 1);	/* Remove the newline */
  msg[strlen(tmp) - 1] = 0;

  ret = cmdret_new (msg, RET_SUCCESS);
  free (msg);
  
  return ret;
}

/* Assign a new number to a window ala screen's number command. */
cmdret *
cmd_number (int interactive, struct cmdarg **args)
{
  int old_number, new_number;
  rp_window_elem *other_win, *win;

  if (args[0] == NULL)
    {
      /* XXX: Fix this. */
      print_window_information (rp_current_group, current_window());
      return cmdret_new (NULL, RET_SUCCESS);
    }

  /* Gather the args. */
  new_number = ARG(0,number);
  if (args[1])
    win = group_find_window_by_number (rp_current_group, ARG(1,number));
  else
    win = group_find_window (&rp_current_group->mapped_windows, current_window());

  /* Make the switch. */
  if ( new_number >= 0 && win)
    {
      /* Find other window with same number and give it old number. */
      other_win = group_find_window_by_number (rp_current_group, new_number);
      if (other_win != NULL)
	{
	  old_number = win->number;
	  other_win->number = old_number;

	  /* Resort the window in the list */
	  group_resort_window (rp_current_group, other_win);
	}
      else
	{
	  numset_release (rp_current_group->numset, win->number);
	}

      win->number = new_number;
      numset_add_num (rp_current_group->numset, new_number);

      /* resort the the window in the list */
      group_resort_window (rp_current_group, win);

      /* Update the window list. */
      update_window_names (win->win->scr);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

/* Toggle the display of the program bar */
cmdret *
cmd_windows (int interactive, struct cmdarg **args)
{
  struct sbuf *window_list = NULL;
  char *tmp;
  int dummy;
  rp_screen *s;

  if (interactive)
    {
      s = current_screen ();
      /* This is a yukky hack. If the bar already hidden then show the
	 bar. This handles the case when msgwait is 0 (the bar sticks)
	 and the user uses this command to toggle the bar on and
	 off. OR the timeout is >0 then show the bar. Which means,
	 always show the bar if msgwait is >0 which fixes the case
	 when a command in the prefix hook displays the bar. */
      if (!hide_bar (s) || defaults.bar_timeout > 0) show_bar (s);
      
      return cmdret_new (NULL, RET_SUCCESS);
    }
  else
    {
      window_list = sbuf_new (0);
      if (args[0])
	get_window_list (ARG_STRING(0), "\n", window_list, &dummy, &dummy);
      else
	get_window_list (defaults.window_fmt, "\n", window_list, &dummy, &dummy);
      tmp = sbuf_get (window_list);
      free (window_list);

      return cmdret_new (tmp, RET_SUCCESS);
    }
}

cmdret *
cmd_abort (int interactive, struct cmdarg **args)
{
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Redisplay the current window by sending 2 resize events. */
cmdret *
cmd_redisplay (int interactive, struct cmdarg **args)
{
  force_maximize (current_window());
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Reassign the prefix key. */
cmdret *
cmd_escape (int interactive, struct cmdarg **args)
{
  struct rp_key *key;
  rp_action *action;
  rp_keymap *map, *top;

  top = find_keymap (TOP_KEYMAP);
  map = find_keymap (ROOT_KEYMAP);
  key = ARG(0,key);

  /* Update the "other" keybinding */
  action = find_keybinding(prefix_key.sym, prefix_key.state, map);
  if (action != NULL && !strcmp (action->data, "other"))
    {
      action->key = key->sym;
      action->state = key->state;
    }

  /* Update the "meta" keybinding */
  action = find_keybinding(prefix_key.sym, 0, map);
  if (action != NULL && !strcmp (action->data, "meta"))
    {
      action->key = key->sym;
      if (key->state != 0)
	action->state = 0;
      else
	action->state = RP_CONTROL_MASK;
    }

  /* Remove the grab on the current prefix key */
  ungrab_keys_all_wins();

  action = find_keybinding(prefix_key.sym, prefix_key.state, top);
  if (action != NULL && !strcmp (action->data, "readkey " ROOT_KEYMAP))
    {
      action->key = key->sym;
      action->state = key->state;
    }

  /* Add the grab for the new prefix key */
  grab_keys_all_wins();

  /* Finally, keep track of the current prefix. */
  prefix_key.sym = key->sym;
  prefix_key.state = key->state;

  return cmdret_new (NULL, RET_SUCCESS);
}

/* User accessible call to display the passed in string. */
cmdret *
cmd_echo (int interactive, struct cmdarg **args)
{
  marked_message_printf (0, 0, "%s", ARG_STRING(0));

  return cmdret_new (NULL, RET_SUCCESS);
}


static cmdret *
read_split (char *str, int max, int *p)
{
  int a, b;
  
  if (sscanf(str, "%d/%d", &a, &b) == 2)
    {
      *p = (int)(max * (float)(a) / (float)(b));
    }
  else if (sscanf(str, "%d", p) == 1)
    {
      if (*p < 0)
	*p = max + *p;
    }
  else
    {
      /* Failed to read input. */
      return cmdret_new_printf (RET_FAILURE, "bad split '%s'", str);
    }

  return NULL;
}

cmdret *
cmd_v_split (int interactive, struct cmdarg **args)
{
  cmdret *ret;
  rp_frame *frame;
  int pixels;

  push_frame_undo (current_screen()); /* fdump to stack */
  frame = current_frame();

  /* Default to dividing the frame in half. */
  if (args[0] == NULL)
    pixels = frame->height / 2;
  else
    {
      ret = read_split (ARG_STRING(0), frame->height, &pixels);
      if (ret)
	return ret;
    }

  if (pixels > 0)
    h_split_frame (frame, pixels);
  else
    return cmdret_new ("vsplit: invalid argument", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_h_split (int interactive, struct cmdarg **args)
{
  cmdret *ret;
  rp_frame *frame;
  int pixels;

  push_frame_undo (current_screen()); /* fdump to stack */
  frame = current_frame();

  /* Default to dividing the frame in half. */
  if (args[0] == NULL)
    pixels = frame->width / 2;
  else
    {
      ret = read_split (ARG_STRING(0), frame->width, &pixels);
      if (ret)
	return ret;
    }

  if (pixels > 0)
    v_split_frame (frame, pixels);
  else
    return cmdret_new ("hsplit: invalid argument", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_only (int interactive, struct cmdarg **args)
{
  push_frame_undo (current_screen()); /* fdump to stack */
  remove_all_splits();
  maximize (current_window());

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_remove (int interactive, struct cmdarg **args)
{
  rp_screen *s = current_screen();
  rp_frame *frame;

  push_frame_undo (current_screen()); /* fdump to stack */

  if (num_frames(s) <= 1)
    {
      return cmdret_new ("remove: cannot remove only frame", RET_FAILURE);
    }

  frame = find_frame_next (current_frame());

  if (frame)
    {
      remove_frame (current_frame());
      set_active_frame (frame);
      show_frame_indicator();
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_shrink (int interactive, struct cmdarg **args)
{
  push_frame_undo (current_screen()); /* fdump to stack */
  resize_shrink_to_window (current_frame());
  return cmdret_new (NULL, RET_SUCCESS);
}

typedef struct resize_binding resize_binding;

struct resize_binding
{
  struct rp_key key;
  enum resize_action {RESIZE_UNKNOWN=0, RESIZE_VGROW, RESIZE_VSHRINK,
      RESIZE_HGROW, RESIZE_HSHRINK, RESIZE_TO_WINDOW,
      RESIZE_ABORT, RESIZE_END } action;
};

static resize_binding resize_bindings[] =
   { {{INPUT_ABORT_KEY,		INPUT_ABORT_MODIFIER},       	RESIZE_ABORT},
     {{RESIZE_VGROW_KEY,	RESIZE_VGROW_MODIFIER}, 	RESIZE_VGROW},
     {{RESIZE_VSHRINK_KEY,	RESIZE_VSHRINK_MODIFIER},	RESIZE_VSHRINK},
     {{RESIZE_HGROW_KEY,	RESIZE_HGROW_MODIFIER}, 	RESIZE_HGROW},
     {{RESIZE_HSHRINK_KEY,	RESIZE_HSHRINK_MODIFIER},	RESIZE_HSHRINK},
     {{RESIZE_SHRINK_TO_WINDOW_KEY,RESIZE_SHRINK_TO_WINDOW_MODIFIER},RESIZE_TO_WINDOW},
     {{RESIZE_END_KEY,		RESIZE_END_MODIFIER},		RESIZE_END},
/* Some more default keys 
 * (after the values from conf.h, so that they have lower priority):
 * first the arrow keys: */
     {{XK_Escape, 		0},          			RESIZE_ABORT},
     {{XK_Down, 		0},           			RESIZE_VGROW},
     {{XK_Up,	 		0},           			RESIZE_VSHRINK},
     {{XK_Right, 		0},           			RESIZE_HGROW},
     {{XK_Left,	 		0},           			RESIZE_HSHRINK},
/* some vi-like bindings: */
     {{XK_j,	 		0},           			RESIZE_VGROW},
     {{XK_k,	 		0},           			RESIZE_VSHRINK},
     {{XK_l,	 		0},           			RESIZE_HGROW},
     {{XK_h,	 		0},           			RESIZE_HSHRINK},
     {{0, 			0},            			RESIZE_UNKNOWN} };


cmdret *
cmd_resize (int interactive, struct cmdarg **args)
{
  rp_screen *s = current_screen ();

  /* If the user calls resize with arguments, treat it like the
     non-interactive version. */
  if (interactive && args[0] == NULL)
    {
      int nbytes;
      char buffer[513];
      unsigned int mod;
      KeySym c;
      struct list_head *bk;

      /* If we haven't got at least 2 frames, there isn't anything to
	 scale. */
      if (num_frames (s) < 2)
	return cmdret_new (NULL, RET_FAILURE);

      XGrabKeyboard (dpy, s->key_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

      /* Save the frameset in case the user aborts. */
      bk = screen_copy_frameset (s);

      while (1)
	{
          struct resize_binding *binding;

	  show_frame_message ("Resize frame");
	  nbytes = read_key (&c, &mod, buffer, sizeof (buffer));

	  /* Convert the mask to be compatible with ratpoison. */
	  mod = x11_mask_to_rp_mask (mod);

	  for (binding = resize_bindings; binding->action; binding++)
            {
              if (c == binding->key.sym && mod == binding->key.state)
                  break;
            }

	  if (binding->action == RESIZE_VGROW)
	    resize_frame_vertically (current_frame(), defaults.frame_resize_unit);
	  else if (binding->action == RESIZE_VSHRINK)
	    resize_frame_vertically (current_frame(), -defaults.frame_resize_unit);
	  else if (binding->action == RESIZE_HGROW)
	    resize_frame_horizontally (current_frame(), defaults.frame_resize_unit);
	  else if (binding->action == RESIZE_HSHRINK)
	    resize_frame_horizontally (current_frame(), -defaults.frame_resize_unit);
	  else if (binding->action == RESIZE_TO_WINDOW)
	    resize_shrink_to_window (current_frame());
	  else if (binding->action == RESIZE_ABORT)
	    {
	      rp_frame *cur;

	      screen_restore_frameset (s, bk);
	      list_for_each_entry (cur, &s->frames, node)
		{
		  maximize_all_windows_in_frame (cur);
		}
	      break;
	    }
	  else if (binding->action == RESIZE_END)
	    {
	      frameset_free (bk);
	      break;
	    }
	}

      /* It is our responsibility to free this. */
      free (bk);

      hide_frame_indicator ();
      XUngrabKeyboard (dpy, CurrentTime);
    }
  else
    {
      if (args[0] && args[1])
	{
	  resize_frame_horizontally (current_frame(), ARG(0,number));
	  resize_frame_vertically (current_frame(), ARG(1,number));
	}
      else
	return cmdret_new ("resize: two numeric arguments required", RET_FAILURE);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_resizeunit (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.frame_resize_unit);

  if (ARG(0,number) >= 0)
    defaults.frame_resize_unit = ARG(0,number);
  else
    return cmdret_new ("defresizeunit: invalid argument", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

/* banish the rat pointer */
cmdret *
cmd_banish (int interactive, struct cmdarg **args)
{
  rp_screen *s;

  s = current_screen ();

  XWarpPointer (dpy, None, s->root, 0, 0, 0, 0, s->left + s->width - 2, s->top + s->height - 2);
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_ratwarp (int interactive, struct cmdarg **args)
{
  rp_screen *s;

  s = current_screen ();
  XWarpPointer (dpy, None, s->root, 0, 0, 0, 0, ARG(0,number), ARG(1,number));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_ratrelwarp (int interactive, struct cmdarg **args)
{
  rp_screen *s;

  s = current_screen ();
  XWarpPointer (dpy, None, None, 0, 0, 0, 0, ARG(0,number), ARG(1,number));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_ratclick (int interactive, struct cmdarg **args)
{
  int button = 1;

  if (args[0])
    {    
      button = ARG(0,number);
      if (button < 1 || button > 3)
	return cmdret_new ("ratclick: invalid argument", RET_SUCCESS);
    }

  XTestFakeButtonEvent(dpy, button, True, CurrentTime);
  XTestFakeButtonEvent(dpy, button, False, CurrentTime);
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_rathold (int interactive, struct cmdarg **args)
{
  int button = 1;

  if (args[1])
    {    
      button = ARG(1,number);
      if (button < 1 || button > 3)
	return cmdret_new ("ratclick: invalid argument", RET_SUCCESS);
    }

  if (!strcmp(ARG_STRING(0), "down"))
    XTestFakeButtonEvent(dpy, button, True, CurrentTime);
  else if(!strcmp(ARG_STRING(0),"up"))
    XTestFakeButtonEvent(dpy, button, False, CurrentTime);
  else
    return cmdret_new_printf (RET_FAILURE, "rathold: '%s' invalid argument", ARG_STRING(0));
  
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_curframe (int interactive, struct cmdarg **args)
{
  show_frame_indicator();
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Thanks to Martin Samuelsson <cosis@lysator.liu.se> for the
   original patch. */
cmdret *
cmd_license (int interactive, struct cmdarg **args)
{
  rp_screen *s = current_screen();
  XEvent ev;
  int x = 10;
  int y = 10;
  int i;
  int max_width = 0;
  char *license_text[] = { PACKAGE " " VERSION, "(built " __DATE__ " " __TIME__ ")",
			   "",
			   "Copyright (C) 2000, 2001, 2002, 2003, 2004 Shawn Betts",
			   "",
			   "ratpoison is free software; you can redistribute it and/or modify ",
			   "it under the terms of the GNU General Public License as published by ",
			   "the Free Software Foundation; either version 2, or (at your option) ",
			   "any later version.",
			   "",
			   "ratpoison is distributed in the hope that it will be useful, ",
			   "but WITHOUT ANY WARRANTY; without even the implied warranty of ",
			   "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the ",
			   "GNU General Public License for more details.",
			   "",
			   "You should have received a copy of the GNU General Public License ",
			   "along with this software; see the file COPYING.  If not, write to ",
			   "the Free Software Foundation, Inc., 59 Temple Place, Suite 330, ",
			   "Boston, MA 02111-1307 USA",
			   "",
			   "Send bugreports, fixes, enhancements, t-shirts, money, beer & pizza ",
			   "to ratpoison-devel@nongnu.org or visit ",
			   "http://www.nongnu.org/ratpoison/",
			   "",
			   "[Press any key to end.] ",
			   NULL};

  XMapRaised (dpy, s->help_window);
  XGrabKeyboard (dpy, s->help_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

  /* Find the longest line. */
  for(i=0; license_text[i]; i++)
    {
      int tmp;

      tmp = XTextWidth (defaults.font, license_text[i], strlen (license_text[i]));
      if (tmp > max_width)
	max_width = tmp;
    }

  /* Offset the text so its in the center. */
  x = s->left + (s->width - max_width) / 2;
  y = s->top + (s->height - i * FONT_HEIGHT (defaults.font)) / 2;
  if (x < 0) x = 0;
  if (y < 0) y = 0;

  /* Print the text. */
  for(i=0; license_text[i]; i++)
  {
    XDrawString (dpy, s->help_window, s->normal_gc,
	         x, y + defaults.font->max_bounds.ascent,
	         license_text[i], strlen (license_text[i]));

    y += FONT_HEIGHT (defaults.font);
  }

  /* Wait for a key press. */
  XMaskEvent (dpy, KeyPressMask, &ev);

  /* Revert focus. */
  XUngrabKeyboard (dpy, CurrentTime);
}

cmdret *
cmd_lock (int interactive, struct cmdarg **args)
{
  rp_keymap *map;

  if (args[0])
    map = ARG(0,keymap);
  else
    map = find_keymap (ROOT_KEYMAP);

  if (interactive)
    {
      rp_screen *s = current_screen();
      XEvent ev;
      int y = 0;
      char *user;
      char *passwd;

      XMapRaised (dpy, s->help_window);
      XGrabKeyboard (dpy, s->help_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

      y += FONT_HEIGHT (defaults.font) * 2;

      XDrawString (dpy, s->help_window, s->normal_gc,
                   10, y + defaults.font->max_bounds.ascent,
                   "Password: ", strlen ("Password: "));

      do {
      passwd = get_password (MESSAGE_PROMPT_COMMAND, null_completions);
      passtok = passwd;
      } while (check_auth());

      XUngrabKeyboard (dpy, CurrentTime);
      XUnmapWindow (dpy, s->help_window);

      /* The help window overlaps the bar, so redraw it. */
      if (current_screen()->bar_is_raised)
        show_last_message();

      return cmdret_new (RET_SUCCESS, NULL);
    }
  else
    {
      struct sbuf *help_list;
      char *tmp;

      return cmdret_new (RET_SUCCESS, "%s", tmp);
    }

  return cmdret_new (RET_SUCCESS, NULL);
}

cmdret *
cmd_help (int interactive, struct cmdarg **args)
{
  rp_keymap *map;

  if (args[0])
    map = ARG(0,keymap);
  else
    map = find_keymap (ROOT_KEYMAP);

  if (interactive)
    {
      rp_screen *s = current_screen();
      XEvent ev;
      int i, old_i;
      int x = 10;
      int y = 0;
      int max_width = 0;
      int drawing_keys = 1;		/* 1 if we are drawing keys 0 if we are drawing commands */
      char *keysym_name;

      XMapRaised (dpy, s->help_window);
      XGrabKeyboard (dpy, s->help_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

      XDrawString (dpy, s->help_window, s->normal_gc,
                   10, y + defaults.font->max_bounds.ascent,
                   "ratpoison key bindings", strlen ("ratpoison key bindings"));

      y += FONT_HEIGHT (defaults.font) * 2;

      XDrawString (dpy, s->help_window, s->normal_gc,
                   10, y + defaults.font->max_bounds.ascent,
                   "Command key: ", strlen ("Command key: "));

      keysym_name = keysym_to_string (prefix_key.sym, prefix_key.state);
      XDrawString (dpy, s->help_window, s->normal_gc,
                   10 + XTextWidth (defaults.font, "Command key: ", strlen ("Command key: ")),
                   y + defaults.font->max_bounds.ascent,
                   keysym_name, strlen (keysym_name));
      free (keysym_name);

      y += FONT_HEIGHT (defaults.font) * 2;

      i = 0;
      old_i = 0;
      while (i<map->actions_last || drawing_keys)
	{
	  if (drawing_keys)
	    {
	      keysym_name = keysym_to_string (map->actions[i].key, map->actions[i].state);

	      XDrawString (dpy, s->help_window, s->normal_gc,
			   x, y + defaults.font->max_bounds.ascent,
			   keysym_name, strlen (keysym_name));

	      if (XTextWidth (defaults.font, keysym_name, strlen (keysym_name)) > max_width)
		max_width = XTextWidth (defaults.font, keysym_name, strlen (keysym_name));

	      free (keysym_name);
	    }
	  else
	    {
	      XDrawString (dpy, s->help_window, s->normal_gc,
			   x, y + defaults.font->max_bounds.ascent,
			   map->actions[i].data, strlen (map->actions[i].data));

	      if (XTextWidth (defaults.font, map->actions[i].data, strlen (map->actions[i].data)) > max_width)
		{
		  max_width = XTextWidth (defaults.font, map->actions[i].data, strlen (map->actions[i].data));
		}
	    }

	  y += FONT_HEIGHT (defaults.font);
	  /* Make sure the next line fits entirely within the window. */
	  if (y + FONT_HEIGHT (defaults.font) >= (s->top + s->height))
	    {
	      if (drawing_keys)
		{
		  x += max_width + 10;
		  drawing_keys = 0;
		  i = old_i;
		}
	      else
		{
		  x += max_width + 20;
		  drawing_keys = 1;
		  i++;
		  old_i = i;
		}

	      max_width = 0;
	      y = FONT_HEIGHT (defaults.font) * 4;
	    }
	  else
	    {
	      i++;
	      if (i >= map->actions_last && drawing_keys)
		{
		  x += max_width + 10;
		  drawing_keys = 0;
		  y = FONT_HEIGHT (defaults.font) * 4;
		  i = old_i;
		  max_width = 0;
		}
	    }
	}

      XMaskEvent (dpy, KeyPressMask, &ev);
      XUngrabKeyboard (dpy, CurrentTime);
      XUnmapWindow (dpy, s->help_window);

      /* The help window overlaps the bar, so redraw it. */
      if (current_screen()->bar_is_raised)
        show_last_message();

      return cmdret_new (NULL, RET_SUCCESS);
    }
  else
    {
      struct sbuf *help_list;
      char *keysym_name;
      char *tmp;
      int i;

      help_list = sbuf_new (0);

      for (i = 0; i < map->actions_last; i++)
	{
	  keysym_name = keysym_to_string (map->actions[i].key, map->actions[i].state);
	  sbuf_concat (help_list, keysym_name);
	  free (keysym_name);
	  sbuf_concat (help_list, " ");
	  sbuf_concat (help_list, map->actions[i].data);
	  if (i < map->actions_last - 1)
	    sbuf_concat (help_list, "\n");
	}

      tmp = sbuf_get (help_list);
      free (help_list);

      return cmdret_new (tmp, RET_SUCCESS);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_rudeness (int interactive, struct cmdarg **args)
{
  int num;

  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d",
			      rp_honour_transient_raise
			      | (rp_honour_normal_raise << 1)
			      | (rp_honour_transient_map << 2)
			      | (rp_honour_normal_map << 3));

  num = ARG(0,number);
  if (num < 0 || num > 15)
    return cmdret_new_printf (RET_FAILURE, "rudeness: invalid level '%s'", ARG_STRING(0));

  rp_honour_transient_raise = num & 1 ? 1 : 0;
  rp_honour_normal_raise    = num & 2 ? 1 : 0;
  rp_honour_transient_map   = num & 4 ? 1 : 0;
  rp_honour_normal_map      = num & 8 ? 1 : 0;

  return cmdret_new (NULL, RET_SUCCESS);
}

static char *
wingravity_to_string (int g)
{
  switch (g)
    {
    case NorthWestGravity:
      return "nw";
    case WestGravity:
      return "w";
    case SouthWestGravity:
      return "sw";
    case NorthGravity:
      return "n";
    case CenterGravity:
      return "c";
    case SouthGravity:
      return "s";
    case NorthEastGravity:
      return "ne";
    case EastGravity:
      return "e";
    case SouthEastGravity:
      return "se";
    }

  PRINT_DEBUG (("Unknown gravity!\n"));
  return "Unknown";
}

cmdret *
cmd_gravity (int interactive, struct cmdarg **args)
{
  int gravity;
  rp_window *win;

  if (current_window() == NULL)
    return cmdret_new (NULL, RET_FAILURE);
  win = current_window();

  if (args[0] == NULL)
    return cmdret_new (wingravity_to_string (win->gravity), RET_SUCCESS);

  if ((gravity = parse_wingravity (ARG_STRING(0))) < 0)
    return cmdret_new ("gravity: unknown gravity", RET_FAILURE);
  else
    {
      win->gravity = gravity;
      maximize (win);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_wingravity (struct cmdarg **args)
{
  if (args[0] == NULL) 
    return cmdret_new (wingravity_to_string (defaults.win_gravity), RET_SUCCESS);

  defaults.win_gravity = ARG(0,gravity);

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_transgravity (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new (wingravity_to_string (defaults.trans_gravity), RET_SUCCESS);

  defaults.trans_gravity = ARG(0,gravity);

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_maxsizegravity (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new (wingravity_to_string (defaults.maxsize_gravity), RET_SUCCESS);

  defaults.maxsize_gravity = ARG(0,gravity);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_msgwait (int interactive, struct cmdarg **args)
{
  if (args[0] == NULL && !interactive)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.bar_timeout);
    
  if (args[0] == NULL)
    return cmdret_new ("msgwait: one argument required", RET_FAILURE);

  if (ARG(0,number) < 0)
    return cmdret_new ("msgwait: invalid argument", RET_FAILURE);
  else
    defaults.bar_timeout = ARG(0,number);

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_bargravity (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new (wingravity_to_string (defaults.bar_location), RET_SUCCESS);

  defaults.bar_location = ARG(0,gravity);

  return cmdret_new (NULL, RET_SUCCESS);
}

static void
update_gc (rp_screen *s)
{
  XGCValues gv;

  gv.foreground = s->fg_color;
  gv.background = s->bg_color;
  gv.function = GXcopy;
  gv.line_width = 1;
  gv.subwindow_mode = IncludeInferiors;
  gv.font = defaults.font->fid;
  XFreeGC (dpy, s->normal_gc);
  s->normal_gc = XCreateGC(dpy, s->root, 
			   GCForeground | GCBackground 
			   | GCFunction | GCLineWidth
			   | GCSubwindowMode | GCFont, &gv);
}

static void
update_all_gcs ()
{
  int i;

  for (i=0; i<num_screens; i++)
    {
      update_gc (&screens[i]);
    }
}

static cmdret *
set_font (struct cmdarg **args)
{
  XFontStruct *font;

  if (args[0] == NULL)
    return cmdret_new (defaults.font_string, RET_SUCCESS);

  font = XLoadQueryFont (dpy, ARG_STRING(0));
  if (font == NULL)
    return cmdret_new ("deffont: unknown font", RET_FAILURE);

  /* Save the font as the default. */
  XFreeFont (dpy, defaults.font);
  defaults.font = font;
  update_all_gcs();

  free (defaults.font_string);
  defaults.font_string = xstrdup (ARG_STRING(0));

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_padding (struct cmdarg **args)
{
  rp_frame *frame;
  int l, t, r, b;

  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d %d %d %d", 
			      defaults.padding_left,
			      defaults.padding_top,
			      defaults.padding_right,
			      defaults.padding_bottom);

  l = ARG(0,number);
  t = ARG(1,number);
  r = ARG(2,number);
  b = ARG(3,number);

  /* Resize the frames to make sure they are not too big and not too
     small. */
  list_for_each_entry (frame,&(current_screen()->frames),node)
    {
      int bk_pos, bk_len;

      /* Resize horizontally. */
      bk_pos = frame->x;
      bk_len = frame->width;

      if (frame->x == defaults.padding_left)
	{
	  frame->x = l;
	  frame->width += bk_pos - l;
	}

      if ((bk_pos + bk_len) == (current_screen()->left + current_screen()->width - defaults.padding_right))
	frame->width = current_screen()->left + current_screen()->width - r - frame->x;

      /* Resize vertically. */
      bk_pos = frame->y;
      bk_len = frame->height;

      if (frame->y == defaults.padding_top)
	{
	  frame->y = t;
	  frame->height += bk_pos - t;
	}

      if ((bk_pos + bk_len) == (current_screen()->top + current_screen()->height - defaults.padding_bottom))
	frame->height = current_screen()->top + current_screen()->height - b - frame->y;

      maximize_all_windows_in_frame (frame);
    }

  defaults.padding_left   = l;
  defaults.padding_right  = r;
  defaults.padding_top 	  = t;
  defaults.padding_bottom = b;

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_border (struct cmdarg **args)
{
  rp_window *win;

  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.window_border_width);

  if (ARG(0,number) < 0)
    return cmdret_new ("defborder: invalid argument", RET_FAILURE);

  defaults.window_border_width = ARG(0,number);

  /* Update all the visible windows. */
  list_for_each_entry (win,&rp_mapped_window,node)
    {
      if (win_get_frame (win))
	maximize (win);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_barborder (struct cmdarg **args)
{
  int i;

  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.bar_border_width);

  if (ARG(0,number) < 0)
    return cmdret_new ("defbarborder: invalid argument", RET_FAILURE);

  defaults.bar_border_width = ARG(0,number);

  /* Update the frame and bar windows. */
  for (i=0; i<num_screens; i++)
    {
      XSetWindowBorderWidth (dpy, screens[i].bar_window, defaults.bar_border_width);
      XSetWindowBorderWidth (dpy, screens[i].frame_window, defaults.bar_border_width);
      XSetWindowBorderWidth (dpy, screens[i].input_window, defaults.bar_border_width);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_inputwidth (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.input_window_size);

  if (ARG(0,number) < 0)
    return cmdret_new ("definputwidth: invalid argument", RET_FAILURE);
  else
    defaults.input_window_size = ARG(0,number);

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_waitcursor (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.wait_for_key_cursor);

  defaults.wait_for_key_cursor = ARG(0,number);
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_winfmt (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new (defaults.window_fmt, RET_SUCCESS);

  free (defaults.window_fmt);
  defaults.window_fmt = xstrdup (ARG_STRING(0));

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_winname (struct cmdarg **args)
{
  char *name;

  if (args[0] == NULL)
    switch (defaults.win_name)
      {
      case WIN_NAME_TITLE:
	return cmdret_new ("title", RET_SUCCESS);
      case WIN_NAME_RES_NAME:
	return cmdret_new ("name", RET_SUCCESS);
      case WIN_NAME_RES_CLASS:
	return cmdret_new ("class", RET_SUCCESS);
      default:
	PRINT_DEBUG (("Unknown win_name\n"));
	return cmdret_new ("unknown", RET_FAILURE);
      }

  name = ARG_STRING(0);

  /* FIXME: Using strncmp is sorta dirty since `title' and
     `titlefoobar' would both match. But its quick and dirty. */
  if (!strncmp (name, "title", 5))
    defaults.win_name = WIN_NAME_TITLE;
  else if (!strncmp (name, "name", 4))
    defaults.win_name = WIN_NAME_RES_NAME;
  else if (!strncmp (name, "class", 5))
    defaults.win_name = WIN_NAME_RES_CLASS;
  else
    return cmdret_new ("defwinname: invalid argument", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_fgcolor (struct cmdarg **args)
{
  int i;
  XColor color, junk;

  if (args[0] == NULL)
    return cmdret_new (defaults.fgcolor_string, RET_SUCCESS);

  for (i=0; i<num_screens; i++)
    {
      if (!XAllocNamedColor (dpy, screens[i].def_cmap, ARG_STRING(0), &color, &junk))
	return cmdret_new ("deffgcolor: unknown color", RET_FAILURE);

      screens[i].fg_color = color.pixel;
      update_gc (&screens[i]);
      XSetWindowBorder (dpy, screens[i].bar_window, color.pixel);
      XSetWindowBorder (dpy, screens[i].input_window, color.pixel);
      XSetWindowBorder (dpy, screens[i].frame_window, color.pixel);
      XSetWindowBorder (dpy, screens[i].help_window, color.pixel);

      free (defaults.fgcolor_string);
      defaults.fgcolor_string = xstrdup (ARG_STRING(0));
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_bgcolor (struct cmdarg **args)
{
  int i;
  XColor color, junk;

  if (args[0] == NULL)
    return cmdret_new (defaults.bgcolor_string, RET_SUCCESS);

  for (i=0; i<num_screens; i++)
    {
      if (!XAllocNamedColor (dpy, screens[i].def_cmap, ARG_STRING(0), &color, &junk))
	return cmdret_new ("defbgcolor: unknown color", RET_FAILURE);

      screens[i].bg_color = color.pixel;
      update_gc (&screens[i]);
      XSetWindowBackground (dpy, screens[i].bar_window, color.pixel);
      XSetWindowBackground (dpy, screens[i].input_window, color.pixel);
      XSetWindowBackground (dpy, screens[i].frame_window, color.pixel);
      XSetWindowBackground (dpy, screens[i].help_window, color.pixel);

      free (defaults.bgcolor_string);
      defaults.bgcolor_string = xstrdup (ARG_STRING(0));
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_setenv (int interactive, struct cmdarg **args)
{
  struct sbuf *env;

  /* Setup the environment string. */
  env = sbuf_new(0);

  sbuf_concat (env, ARG_STRING(0));
  sbuf_concat (env, "=");
  sbuf_concat (env, ARG_STRING(1));

  /* Stick it in the environment. */
  PRINT_DEBUG(("%s\n", sbuf_get(env)));
  putenv (sbuf_get (env));

  /* According to the docs, the actual string is placed in the
     environment, not the data the string points to. This means
     modifying the string (or freeing it) directly changes the
     environment. So, don't free the environment string, just the sbuf
     data structure. */
  env->data = NULL;
  sbuf_free (env);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_getenv (int interactive, struct cmdarg **args)
{
  char *value;

  value = getenv (ARG_STRING(0));
  return cmdret_new (value, RET_SUCCESS);
}

/* Thanks to Gergely Nagy <algernon@debian.org> for the original
   patch. */
cmdret *
cmd_chdir (int interactive, struct cmdarg **args)
{
  char *dir;

  if (args[0] == NULL)
    {
      dir = getenv ("HOME");
      if (dir == NULL || *dir == '\0')
        {
	  return cmdret_new ("chdir: HOME not set", RET_FAILURE);
	}
    }
  else
    dir = ARG_STRING(0);

  if (chdir (dir) == -1)
    return cmdret_new_printf (RET_FAILURE, "chdir: %s: %s", dir, strerror(errno));

  return cmdret_new (NULL, RET_SUCCESS);
}

/* Thanks to Gergely Nagy <algernon@debian.org> for the original
   patch. */
cmdret *
cmd_unsetenv (int interactive, struct cmdarg **args)
{
  struct sbuf *s;

  /* Remove all instances of the env. var. We must add an '=' for it
     to work on OpenBSD. */
  s = sbuf_new(0);
  sbuf_copy (s, ARG_STRING(0));
  sbuf_concat (s, "=");
/*   str = sbuf_free_struct (s); */
  putenv (sbuf_get(s));
  sbuf_free (s);
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Thanks to Gergely Nagy <algernon@debian.org> for the original
   patch. */
cmdret *
cmd_info (int interactive, struct cmdarg **args)
{
  if (current_window() == NULL)
    return cmdret_new_printf (RET_SUCCESS, "(%d, %d) No window", 
			      current_screen()->width, current_screen()->height);
  else
    {
      rp_window *win = current_window();
      rp_window_elem *win_elem;
      win_elem = group_find_window (&rp_current_group->mapped_windows, win);
      if (win_elem)
	return cmdret_new_printf (RET_SUCCESS, "(%d,%d) %d(%s)%s", win->width, win->height,
				  win_elem->number, window_name (win), 
				  win->transient ? " Transient":"");
      else
	return cmdret_new_printf (RET_SUCCESS, "(%d,%d) (%s)%s", win->width, win->height,
				  window_name (win), win->transient ? " Transient":"");
    }
}

/* Thanks to Gergely Nagy <algernon@debian.org> for the original
   patch. */
cmdret *
cmd_lastmsg (int interactive, struct cmdarg **args)
{
  show_last_message();
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_focusup (int interactive, struct cmdarg **args)
{
  rp_frame *frame;

  if ((frame = find_frame_up (current_frame())))
    set_active_frame (frame);
  else
    show_frame_indicator();

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_focusdown (int interactive, struct cmdarg **args)
{
  rp_frame *frame;

  if ((frame = find_frame_down (current_frame())))
    set_active_frame (frame);
  else
    show_frame_indicator();

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_focusleft (int interactive, struct cmdarg **args)
{
  rp_frame *frame;

  if ((frame = find_frame_left (current_frame())))
    set_active_frame (frame);
  else
    show_frame_indicator();

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_focusright (int interactive, struct cmdarg **args)
{
  rp_frame *frame;

  if ((frame = find_frame_right (current_frame())))
    set_active_frame (frame);
  else
    show_frame_indicator();

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_restart (int interactive, struct cmdarg **args)
{
  hup_signalled = 1;
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_startup_message (int interactive, struct cmdarg **args)
{
  if (args[0] == NULL && !interactive)
    return cmdret_new_printf (RET_SUCCESS, "%s", defaults.startup_message ? "on":"off");

  if (!strcasecmp (ARG_STRING(0), "on"))
    defaults.startup_message = 1;
  else if (!strcasecmp (ARG_STRING(0), "off"))
    defaults.startup_message = 0;
  else
    return cmdret_new ("startup_message: invalid argument", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_focuslast (int interactive, struct cmdarg **args)
{
  rp_frame *frame = find_last_frame();

  if (frame)
      set_active_frame (frame);
  else
    return cmdret_new ("focuslast: no other frame", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_link (int interactive, struct cmdarg **args)
{
  char *cmd = NULL;
  rp_keymap *map;

  if (args[1])
    map = ARG(1,keymap);
  else
    map = find_keymap (ROOT_KEYMAP);

  cmd = resolve_command_from_keydesc (args[0]->string, 0, map);
  if (cmd)
    return command (interactive, cmd);

  return cmdret_new (NULL, RET_SUCCESS);
}

/* Thanks to Doug Kearns <djkea2@mugc.its.monash.edu.au> for the
   original patch. */
static cmdret *
set_barpadding (struct cmdarg **args)
{
  int x, y;

  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d %d", defaults.bar_x_padding, defaults.bar_y_padding);

  x = ARG(0,number);
  y = ARG(1,number);

  if (x >= 0 && y >= 0)
    {
      defaults.bar_x_padding = x;
      defaults.bar_y_padding = y;
    }
  else
    return cmdret_new ("defbarpadding: invalid arguments", RET_FAILURE);    

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_alias (int interactive, struct cmdarg **args)
{
  /* Add or update the alias. */
  add_alias (ARG_STRING(0), ARG_STRING(1));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_unalias (int interactive, struct cmdarg **args)
{
  int index;

  /* Are we updating an existing alias, or creating a new one? */
  index = find_alias_index (ARG_STRING(0));
  if (index >= 0)
    {
      char *tmp;

      alias_list_last--;

      /* Free the alias and put the last alias in the the space to
	 keep alias_list from becoming sparse. This code must jump
	 through some hoops to correctly handle the case when
	 alias_list_last == index. */
      tmp = alias_list[index].alias;
      alias_list[index].alias = xstrdup (alias_list[alias_list_last].alias);
      free (tmp);
      free (alias_list[alias_list_last].alias);

      /* Do the same for the name element. */
      tmp = alias_list[index].name;
      alias_list[index].name = xstrdup (alias_list[alias_list_last].name);
      free (tmp);
      free (alias_list[alias_list_last].name);
    }
  else
    return cmdret_new ("unalias: alias not found", RET_SUCCESS);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_nextscreen (int interactive, struct cmdarg **args)
{
  int new_screen;

  /* No need to go through the motions when we don't have to. */
  if (num_screens <= 1)
    return cmdret_new ("nextscreen: no other screen", RET_FAILURE);

  new_screen = rp_current_screen + 1;
  if (new_screen >= num_screens)
    new_screen = 0;

  set_active_frame (screen_get_frame (&screens[new_screen], screens[new_screen].current_frame));

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_prevscreen (int interactive, struct cmdarg **args)
{
  int new_screen;

  /* No need to go through the motions when we don't have to. */
  if (num_screens <= 1)
    return cmdret_new ("prevscreen: no other screen", RET_SUCCESS);

  new_screen = rp_current_screen - 1;
  if (new_screen < 0)
    new_screen = num_screens - 1;

  set_active_frame (screen_get_frame (&screens[new_screen], screens[new_screen].current_frame));

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_sselect(int interactive, struct cmdarg **args)
{
  int new_screen;

  new_screen = ARG(0,number);
  if (new_screen < 0)
    return cmdret_new ("sselect: out of range", RET_FAILURE);

  if (new_screen < num_screens)
    set_active_frame (screen_get_frame (&screens[new_screen], screens[new_screen].current_frame));
  else
    return cmdret_new ("sselect: out of range", RET_FAILURE);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_warp (int interactive, struct cmdarg **args)
{
  if (args[0] == NULL && !interactive)
    return cmdret_new_printf (RET_SUCCESS, "%s", defaults.warp ? "on":"off");

  if (!strcasecmp (ARG_STRING(0), "on"))
    defaults.warp = 1;
  else if (!strcasecmp (ARG_STRING(0), "off"))
    defaults.warp = 0;
  else
    return cmdret_new ("warp: invalid argument", RET_FAILURE);
 
  return cmdret_new (NULL, RET_SUCCESS);
}

static void
sync_wins (rp_screen *s)
{
  rp_window *win, *wintmp;
  XWindowAttributes attr;
  unsigned int i, nwins;
  Window dw1, dw2, *wins;
  XQueryTree(dpy, s->root, &dw1, &dw2, &wins, &nwins);

  /* Remove any windows in our cached lists that aren't in the query
     tree. These windows have been destroyed. */
  list_for_each_entry_safe (win, wintmp, &rp_mapped_window, node)
    {
      int found;

      found = 0;
      for (i=0; i<nwins; i++)
	{
	  if (win->w == wins[i])
	    {
	      found = 1;
	      break;
	    }
	}
      if (!found)
	{
	  ignore_badwindow++;  

	  /* If, somehow, the window is not withdrawn before it is destroyed,
	     perform the necessary steps to withdraw the window before it is
	     unmanaged. */
	  if (win->state == IconicState)
	    {
	      PRINT_DEBUG (("Destroying Iconic Window (%s)\n", window_name (win)));
	      withdraw_window (win);
	    }
	  else if (win->state == NormalState)
	    {
	      rp_frame *frame;

	      PRINT_DEBUG (("Destroying Normal Window (%s)\n", window_name (win)));
	      frame = find_windows_frame (win);
	      if (frame)
		{
		  cleanup_frame (frame);
		  if (frame->number == win->scr->current_frame) 
		    set_active_frame (frame);
		}
	      withdraw_window (win);
	    }

	  /* Now that the window is guaranteed to be in the unmapped window
	     list, we can safely stop managing it. */
	  unmanage (win);
	  ignore_badwindow--;
	}
    }

  for (i=0; i<nwins; i++)
    {
      XGetWindowAttributes(dpy, wins[i], &attr);
      if (wins[i] == s->bar_window 
	  || wins[i] == s->key_window 
	  || wins[i] == s->input_window
	  || wins[i] == s->frame_window
	  || wins[i] == s->help_window
	  || attr.override_redirect == True) continue;
      
      /* Find the window in our mapped window list. */
      win = find_window_in_list (wins[i], &rp_mapped_window);
      if (win)
	{
	  rp_frame *frame;
	  /* If the window is viewable and it is in a frame, then
	     maximize it and go to the next window. */
	  if (attr.map_state == IsViewable)
	    {
	      frame = find_windows_frame (win);
	      if (frame)
		{
		  maximize (win);
		}
	      else
		{
		  hide_window (win);
		}
	    }
	  else if (attr.map_state == IsUnmapped
		   && get_state (win) == IconicState)
	    {
	      frame = find_windows_frame (win);
	      if (frame)
		{
		  unhide_window (win);
		  maximize (win);
		}
	    }
	  else
	    {
	      PRINT_DEBUG (("I don't know what to do...\n"));
	    }
	  
	  /* We've handled the window. */
	  continue;
	}

      /* Try the unmapped window list. */
      win = find_window_in_list (wins[i], &rp_unmapped_window);
      if (win)
	{
	  /* If the window is viewable and it is in a frame, then
	     maximize it and go to the next window. */
	  if (attr.map_state == IsViewable)
	    {
	      /* We need to map it since it's visible now. */
	      map_window (win);
	    }
	  else if (attr.map_state == IsUnmapped
		   && get_state (win) == IconicState)
	    {
	      /* We need to map the window and then hide it. */
	      map_window (win);
	      hide_window (win);
	    }
	  else
	    {
	      PRINT_DEBUG (("I think it's all sync'd up...\n"));
	    }
	  
	  /* We've handled the window. */
	  continue;
	}

      /* The window isn't in the mapped or unmapped window list so add
	 it. */
      win = add_to_window_list (s, wins[i]);
      
      /* If it's visible or iconized. "Map" it. */
      if (attr.map_state == IsViewable
	  || (attr.map_state == IsUnmapped
	      && get_state (win) == IconicState))
	map_window (win);
    }

}

/* Temporarily give control over to another window manager, reclaiming */
/*    control when that WM terminates. */
cmdret *
cmd_tmpwm (int interactive, struct cmdarg **args)
{
  struct list_head *tmp, *iter;
  rp_window *win = NULL;
  int child;
  int status;
  int pid;
  int i;

  push_frame_undo (current_screen()); /* fdump to stack */

  /* Release event selection on the root windows, so the new WM can
     have it. */
  for (i=0; i<num_screens; i++)
    {
      XSelectInput(dpy, RootWindow (dpy, screens[i].screen_num), 0);
      /* Unmap its key window */
      XUnmapWindow (dpy, screens[i].key_window);
    }

  /* Don't listen for any events from any window. */
  list_for_each_safe_entry (win, iter, tmp, &rp_mapped_window, node)
    {
      unhide_window (win);
      maximize (win);
      XSelectInput (dpy, win->w, 0);
    }

  list_for_each_safe_entry (win, iter, tmp, &rp_unmapped_window, node)
    XSelectInput (dpy, win->w, 0);

  XSync (dpy, False);

  /* Launch the new WM and wait for it to terminate. */
  pid = spawn (ARG_STRING(0));
  do
    {
      child = waitpid (pid, &status, 0);
    } while (child != pid);

  /* This xsync seems to be needed. Otherwise, the following code dies
     because X thinks another WM is running. */
  XSync (dpy, False);

  /* Enable the event selection on the root window. */
  for (i=0; i<num_screens; i++)
    {
      XSelectInput(dpy, RootWindow (dpy, screens[i].screen_num),
		   PropertyChangeMask | ColormapChangeMask
		   | SubstructureRedirectMask | SubstructureNotifyMask);
      /* Map its key window */
      XMapWindow (dpy, screens[i].key_window);
    }
  XSync (dpy, False);

  /* Sort through all the windows in each group and pick out the ones
     that are unmapped or destroyed. */
  for (i=0; i<num_screens; i++)
    {
      sync_wins (&screens[i]);
    }

  /* If no window has focus, give the key_window focus. */
  if (current_window())
    set_active_window (current_window());
  else
    set_window_focus (current_screen()->key_window);

  /* And we're back in ratpoison. */
  return cmdret_new (NULL, RET_SUCCESS);
}

/* Return a new string with the frame selector or it as a string if no
   selector exists for the number. */

/* Select a frame by number. */
cmdret *
cmd_fselect (int interactive, struct cmdarg **args)
{
  set_active_frame (ARG(0,frame));
  if (interactive)
    return cmdret_new (NULL, RET_SUCCESS);
  else
    return cmdret_new_printf (RET_SUCCESS, "%d", ARG(0,frame)->number);
}

static char *
fdump (rp_screen *screen)
{
  struct sbuf *s;
  char *tmp;
  rp_frame *cur;

  s = sbuf_new (0);

  /* FIXME: Oooh, gross! there's a trailing comma, yuk! */
  list_for_each_entry (cur, &(screen->frames), node)
    {
      char *tmp;

      tmp = frame_dump (cur);
      sbuf_concat (s, tmp);
      sbuf_concat (s, ",");
      free (tmp);
    }

  tmp = sbuf_get (s);
  free (s);
  return tmp;
}

cmdret *
cmd_fdump (int interactively, struct cmdarg **args)
{
  if (args[0] == NULL)
    {
      char *s = fdump (current_screen());
      cmdret *ret = cmdret_new (s, RET_SUCCESS);
      free (s);
      return ret;
    }
  else
    {
      int snum;
      snum = ARG(0,number);

      if (snum < 0 || num_screens <= snum)
	return cmdret_new ("fdump: invalid argument", RET_FAILURE);
      else
	{
	  char *s = fdump (&screens[snum]);
	  cmdret *ret = cmdret_new (s, RET_SUCCESS);
	  free (s);
	  return ret;
	}
    }
}

static cmdret *
frestore (char *data, rp_screen *s)
{
  char *token;
  char *dup;
  rp_frame *new, *cur;
  rp_window *win;
  struct list_head fset;
  int max = -1;
  char *nexttok;

  INIT_LIST_HEAD (&fset);

  dup = xstrdup (data);
  token = strtok_r (dup, ",", &nexttok);
  if (token == NULL)
    {
      free (dup);
      return cmdret_new ("frestore: invalid frame format", RET_FAILURE);
    }

  /* Build the new frame set. */
  while (token != NULL)
    {
      new = frame_read (token);
      if (new == NULL)
	{
	  free (dup);
	  return cmdret_new ("frestore: invalid frame format", RET_SUCCESS);;
	}
      list_add_tail (&new->node, &fset);
      token = strtok_r (NULL, ",", &nexttok);
    } 

  free (dup);

  /* Clear all the frames. */
  list_for_each_entry (cur, &s->frames, node)
    {
      PRINT_DEBUG (("blank %d\n", cur->number));
      blank_frame (cur);
    }

  /* Get rid of the frames' numbers */
  screen_free_nums (s);

  /* Splice in our new frameset. */
  screen_restore_frameset (s, &fset);
/*   numset_clear (s->frames_numset); */

  /* Process the frames a bit to make sure everything lines up. */
  list_for_each_entry (cur, &s->frames, node)
    {
      rp_window *win;

      PRINT_DEBUG (("restore %d %d\n", cur->number, cur->win_number));

      /* Grab the frame's number, but if it already exists request a
	 new one. */
      if (!numset_add_num (s->frames_numset, cur->number)) {
	cur->number = numset_request (s->frames_numset);
      }

      /* Find the current frame based on last_access. */
      if (cur->last_access > max)
	{
	  s->current_frame = cur->number;
	  max = cur->last_access;
	}

      /* Update the window the frame points to. */
      if (cur->win_number != EMPTY)
	{
	  win = find_window_number (cur->win_number);
	  set_frames_window (cur, win);
	}
    }

  /* Show the windows in the frames. */
  list_for_each_entry (win, &rp_mapped_window, node)
    {
      if (win->frame_number != EMPTY)
	{
	  maximize (win);
	  unhide_window (win);
	}
    }

  set_active_frame (current_frame());  
  update_bar (s);
  show_frame_indicator();

  PRINT_DEBUG (("Done.\n"));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_frestore (int interactively, struct cmdarg **args)
{
  push_frame_undo (current_screen()); /* fdump to stack */
  return frestore (ARG_STRING(0), current_screen());
}

cmdret *
cmd_verbexec (int interactive, struct cmdarg **args)
{
  marked_message_printf(0, 0, "Running %s", ARG_STRING(0));
  spawn (ARG_STRING(0));
  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_winliststyle (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%s", defaults.window_list_style ? "column":"row");

  if (!strcmp ("column", ARG_STRING(0)))
    defaults.window_list_style = STYLE_COLUMN;
  else if (!strcmp ("row", ARG_STRING(0)))
    defaults.window_list_style = STYLE_ROW;
  else
    return cmdret_new ("defwinliststyle: invalid argument", RET_FAILURE);

   return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_gnext (int interactive, struct cmdarg **args)
{
  set_current_group (group_next_group ());
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_gprev (int interactive, struct cmdarg **args)
{
  set_current_group (group_prev_group ());
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_gnew (int interactive, struct cmdarg **args)
{
  set_current_group (group_add_new_group (ARG_STRING(0)));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_gnewbg (int interactive, struct cmdarg **args)
{
  group_add_new_group (ARG_STRING(0));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_gselect (int interactive, struct cmdarg **args)
{
  rp_group *g;

  g = find_group (ARG_STRING(0));

  if (g)
    set_current_group (g);
  else
    return cmd_groups (interactive, NULL);

  return cmdret_new (NULL, RET_SUCCESS);
}

/* Show all the groups, with the current one highlighted. */
cmdret *
cmd_groups (int interactive, struct cmdarg **args)
{
  rp_group *cur;
  int mark_start = 0, mark_end = 0;
  struct sbuf *buffer;

  buffer = sbuf_new (0);

  /* Generate the string. */
  list_for_each_entry (cur, &rp_groups, node)
    {
      char *fmt;
      char separator;

      if (cur == rp_current_group)
	mark_start = strlen (sbuf_get (buffer));

      /* Pad start of group name with a space for row
	 style. non-Interactive always gets a column.*/
      if (defaults.window_list_style == STYLE_ROW && interactive)
	  sbuf_concat (buffer, " ");

      if(cur == rp_current_group)
	separator = '*';
      else
	separator = '-';

      fmt = xsprintf ("%d%c%s", cur->number, separator, cur->name);
      sbuf_concat (buffer, fmt);

      /* Pad end of group name with a space for row style. */
      if (defaults.window_list_style == STYLE_ROW && interactive)
	{
	  sbuf_concat (buffer, " ");
	}
      else
	{
	  if (cur->node.next != &rp_groups)
	    sbuf_concat (buffer, "\n");
	}

      if (cur == rp_current_group)
	mark_end = strlen (sbuf_get (buffer));
    }

  /* Display it or return it. */
  if (interactive)
    {
      marked_message (sbuf_get (buffer), mark_start, mark_end);
      sbuf_free (buffer);
      return cmdret_new (NULL, RET_SUCCESS);
    }
  else
    {
      cmdret *ret = cmdret_new (sbuf_get(buffer), RET_SUCCESS);
      sbuf_free(buffer);
      return ret;
    }
}

/* Move a window to a different group. */
cmdret *
cmd_gmove (int interactive, struct cmdarg **args)
{
  if (current_window() == NULL)
    return cmdret_new ("gmove: no focused window", RET_FAILURE);

  group_move_window (ARG(0,group), current_window());
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_gmerge (int interactive, struct cmdarg **args)
{
  groups_merge (ARG(0,group), rp_current_group);
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_addhook (int interactive, struct cmdarg **args)
{
  struct list_head *hook;
  struct sbuf *cmd;
  
  hook = hook_lookup (ARG_STRING(0));
  if (hook == NULL)
    return cmdret_new_printf (RET_FAILURE, "addhook: unknown hook '%s'", ARG_STRING(0));

  /* Add the command to the hook */
  cmd = sbuf_new (0);
  sbuf_copy (cmd, ARG_STRING(1));
  hook_add (hook, cmd);

  free (dup);
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_remhook (int interactive, struct cmdarg **args)
{
  struct sbuf *cmd;

  /* Remove the command from the hook */
  cmd = sbuf_new (0);
  sbuf_copy (cmd, ARG_STRING(1));
  hook_remove (ARG(0,hook), cmd);
  sbuf_free (cmd);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_listhook (int interactive, struct cmdarg **args)
{
  cmdret *ret;
  struct sbuf *buffer;
  struct list_head *hook;
  struct sbuf *cur;

  hook = hook_lookup (ARG_STRING(0));
  if (hook == NULL)
    return cmdret_new_printf (RET_FAILURE, "listhook: unknown hook '%s'", ARG_STRING(0));

  if (list_empty(hook))
    return cmdret_new_printf (RET_FAILURE, " Nothing defined for %s ", ARG_STRING(0));

  buffer = sbuf_new(0);

  list_for_each_entry (cur, hook, node)
    {
      sbuf_printf_concat(buffer, "%s", sbuf_get (cur));
      if (cur->node.next != hook)
	sbuf_printf_concat(buffer, "\n");
    }

  ret = cmdret_new (sbuf_get (buffer), RET_SUCCESS);
  sbuf_free (buffer);
  return ret;
}

cmdret *
cmd_gdelete (int interactive, struct cmdarg **args)
{
  rp_group *g;

  if (args[0] == NULL)
    g = rp_current_group;
  else
    g = ARG(0,group);
  
  switch (group_delete_group (g))
    {
    case GROUP_DELETE_GROUP_OK:
      break;
    case GROUP_DELETE_GROUP_NONEMPTY:
      return cmdret_new ("gdelete: non-empty group", RET_FAILURE);
      break;
    default:
      return cmdret_new ("gdelete: unknown return code (this shouldn't happen)", RET_FAILURE);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

static void
grab_rat ()
{
  XGrabPointer (dpy, current_screen()->root, True, 0, 
		GrabModeAsync, GrabModeAsync, 
		None, current_screen()->rat, CurrentTime);
}

static void
ungrab_rat ()
{
  XUngrabPointer (dpy, CurrentTime);
}

cmdret *
cmd_readkey (int interactive, struct cmdarg **args)
{
  char *keysym_name;
  rp_action *key_action;
  KeySym keysym;		/* Key pressed */
  unsigned int mod;		/* Modifiers */
  int rat_grabbed = 0;
  rp_keymap *map;

  map = ARG(0,keymap);

  XGrabKeyboard (dpy, current_screen()->key_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

  /* Change the mouse icon to indicate to the user we are waiting for
     more keystrokes */
  if (defaults.wait_for_key_cursor)
    {
      grab_rat();
      rat_grabbed = 1;
    }

  read_key (&keysym, &mod, NULL, 0);
  XUngrabKeyboard (dpy, CurrentTime);

  if (rat_grabbed)
    ungrab_rat();

  if ((key_action = find_keybinding (keysym, x11_mask_to_rp_mask (mod), map)))
    {
      return command (1, key_action->data);
    }
  else
    {
      cmdret *ret;
      /* No key match, notify user. */
      keysym_name = keysym_to_string (keysym, x11_mask_to_rp_mask (mod));
      ret = cmdret_new_printf (RET_FAILURE, "readkey: unbound key '%s'", keysym_name);
      free (keysym_name);
      return ret;
    }
}

cmdret *
cmd_newkmap (int interactive, struct cmdarg **args)
{
  rp_keymap *map;

  map = find_keymap (ARG_STRING(0));
  if (map)
    return cmdret_new_printf (RET_FAILURE, "newkmap: keymap '%s' already exists", ARG_STRING(0));

  map = keymap_new (ARG_STRING(0));
  list_add_tail (&map->node, &rp_keymaps);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_delkmap (int interactive, struct cmdarg **args)
{
   rp_keymap *map, *top, *root;

  top = find_keymap (TOP_KEYMAP);
  root = find_keymap (ROOT_KEYMAP);

  map = ARG(0,keymap);
  if (map == root || map == top)
    return cmdret_new_printf (RET_FAILURE, "delkmap: cannot delete keymap '%s'", ARG_STRING(0));

  list_del (&map->node);

  return cmdret_new (NULL, RET_SUCCESS);
}

static cmdret *
set_framesels (struct cmdarg **args)
{
  if (args[0] == NULL)
    return cmdret_new (defaults.frame_selectors, RET_SUCCESS);

  free (defaults.frame_selectors);
  defaults.frame_selectors = xstrdup (ARG_STRING(0));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_set (int interactive, struct cmdarg **args)
{
  if (args[0] == NULL)
    {
      /* List all the settings. */
      cmdret *ret;
      struct sbuf *s = sbuf_new(0);
      struct set_var *cur, *last;

      list_last (last, &set_vars, node);
      list_for_each_entry (cur, &set_vars, node)
	{
	  cmdret *ret;
	  ret = cur->set_fn (args);
	  sbuf_printf_concat (s, "%s: %s", cur->var, ret->output);
	  /* Skip a newline on the last line. */
	  if (cur != last)
	    sbuf_concat (s, "\n");
	  cmdret_free (ret);
	}
	  
      /* Return the accumulated string. */
      ret = cmdret_new (sbuf_get (s), RET_SUCCESS);
      sbuf_free (s);
      return ret;
    }
  else
    {
      struct sbuf *scur;
      struct cmdarg *acur;
      struct list_head *iter, *tmp;
      struct list_head head, arglist;
      int i, nargs = -1;
      int parsed_args;
      cmdret *result = NULL;
      struct cmdarg **cmdargs;
      char *input;

      INIT_LIST_HEAD (&arglist);
      INIT_LIST_HEAD (&head);

      /* We need to tell parse_args about arg_REST and arg_SHELLCMD. */
      for (i=0; i<ARG(0,variable)->nargs; i++)
	if (ARG(0,variable)->args[i].type == arg_REST
	    || ARG(0,variable)->args[i].type == arg_SHELLCMD
	    || ARG(0,variable)->args[i].type == arg_RAW)
	  {
	    nargs = i;
	    break;
	  }

      /* Parse the arguments and call the function. */
      if (args[1])
	input = xstrdup (args[1]->string);
      else
	input = xstrdup ("");
      result = parse_args (input, &head, nargs, ARG(0,variable)->args[i].type == arg_RAW);
      free (input);

      if (result)
	goto failed;
      result = parsed_input_to_args (ARG(0,variable)->nargs, ARG(0,variable)->args,
				     &head, &arglist, &parsed_args);
      if (result)
	goto failed;
      /* 0 or nargs is acceptable */
      if (list_size (&arglist) > 0 && list_size (&arglist) < ARG(0,variable)->nargs)
	{
	  result = cmdret_new ("not enough arguments.", RET_FAILURE);
	  goto failed;
	}
      else if (list_size (&head) > ARG(0,variable)->nargs)
	{
	  result = cmdret_new ("too many arguments.", RET_FAILURE);
	  goto failed;
	}

      cmdargs = arg_array (&arglist);
      result = ARG(0,variable)->set_fn (cmdargs);
      free (cmdargs);

      /* Free the lists. */
    failed:
      /* Free the parsed strings */
      list_for_each_safe_entry (scur, iter, tmp, &head, node)
	sbuf_free(scur);
      /* Free the args */
      list_for_each_safe_entry (acur, iter, tmp, &arglist, node)
	arg_free (acur);

      return result;
    }
}

cmdret *
cmd_sfdump (int interactively, struct cmdarg **args)
{
  cmdret *ret;
  struct sbuf *s;
  char *tmp2;
  rp_frame *cur;
  int i;

  s = sbuf_new (0);

  for (i=0; i<num_screens; i++)
    {
      tmp2 = xsprintf (" %d,", (rp_have_xinerama)?(screens[i].xine_screen_num):(screens[i].screen_num));

      /* FIXME: Oooh, gross! there's a trailing comma, yuk! */
      list_for_each_entry (cur, &(screens[i].frames), node)
	{
	  char *tmp;

	  tmp = frame_dump (cur);
	  sbuf_concat (s, tmp);
	  sbuf_concat (s, tmp2);
	  free (tmp);
	}

      free (tmp2);
    }
  ret = cmdret_new (sbuf_get (s), RET_SUCCESS);
  sbuf_free (s);
  return ret;
}

cmdret *
cmd_sdump (int interactive, struct cmdarg **args)
{
  cmdret *ret;
  struct sbuf *s;
  char *tmp;
  int i;

  s = sbuf_new (0);
  for (i=0; i<num_screens; ++i)
  {
    tmp = screen_dump (&screens[i]);
    sbuf_concat (s, tmp);
    if (i + 1 != num_screens)	/* No trailing comma. */
      sbuf_concat (s, ",");
    free (tmp);
  }

  ret = cmdret_new (sbuf_get (s), RET_SUCCESS);
  sbuf_free (s);
  return ret;
}

static cmdret *
set_maxundos (struct cmdarg **args)
{
  rp_frame_undo *cur;

  if (args[0] == NULL)
    return cmdret_new_printf (RET_SUCCESS, "%d", defaults.maxundos);

  if (ARG(0,number) < 0)
    return cmdret_new ("defmaxundos: invalid argument", RET_FAILURE);

  defaults.maxundos = ARG(0,number);

  /* Delete any superfluous undos */
  while (rp_num_frame_undos > defaults.maxundos)
    {
      /* Delete the oldest node */
      list_last (cur, &rp_frame_undos, node);
      pop_frame_undo (cur);
    }

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_cnext (int interactive, struct cmdarg **args)
{
  rp_window *cur, *last, *win;

  cur = current_window();
  if (!cur || !cur->res_class)	/* Can't be done. */
    return cmd_next (interactive, args);

  /* CUR !in cycle list, so LAST marks last node. */
  last = group_prev_window (rp_current_group, cur);

  if (last)
    for (win = group_next_window (rp_current_group, cur);
	 win;
	 win = group_next_window (rp_current_group, win))
      {
	if (win->res_class
	    && strcmp (cur->res_class, win->res_class))
	  {
	    set_active_window_force (win);
	    return cmdret_new (NULL, RET_SUCCESS);
	  }

	if (win == last) break;
      }

  return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
}

cmdret *
cmd_cprev (int interactive, struct cmdarg **args)
{
  rp_window *cur, *last, *win;

  cur = current_window();
  if (!cur || !cur->res_class)	/* Can't be done. */
    return cmd_next (interactive, args);

  /* CUR !in cycle list, so LAST marks last node. */
  last = group_next_window (rp_current_group, cur);

  if (last)
    for (win = group_prev_window (rp_current_group, cur);
	 win;
	 win = group_prev_window (rp_current_group, win))
      {
	if (win->res_class
	    && strcmp (cur->res_class, win->res_class))
	  {
	    set_active_window_force (win);
	    return cmdret_new (NULL, RET_SUCCESS);
	  }

	if (win == last) break;
      }

  return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
}

cmdret *
cmd_inext (int interactive, struct cmdarg **args)
{
  rp_window *cur, *last, *win;

  cur = current_window();
  if (!cur || !cur->res_class)	/* Can't be done. */
    return cmd_next (interactive, args);

  /* CUR !in cycle list, so LAST marks last node. */
  last = group_prev_window (rp_current_group, cur);

  if (last)
    for (win = group_next_window (rp_current_group, cur);
	 win;
	 win = group_next_window (rp_current_group, win))
      {
	if (win->res_class
	    && !strcmp (cur->res_class, win->res_class))
	  {
	    set_active_window_force (win);
	    return cmdret_new (NULL, RET_SUCCESS);
	  }

	if (win == last) break;
      }

  return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
}

cmdret *
cmd_iprev (int interactive, struct cmdarg **args)
{
  rp_window *cur, *last, *win;

  cur = current_window();
  if (!cur || !cur->res_class)	/* Can't be done. */
    return cmd_next (interactive, args);

  /* CUR !in cycle list, so LAST marks last node. */
  last = group_next_window (rp_current_group, cur);

  if (last)
    for (win = group_prev_window (rp_current_group, cur);
	 win;
	 win = group_prev_window (rp_current_group, win))
      {
	if (win->res_class
	    && !strcmp (cur->res_class, win->res_class))
	  {
	    set_active_window_force (win);
	    return cmdret_new (NULL, RET_SUCCESS);
	  }
	
	if (win == last) break;
      }

  return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
}

cmdret *
cmd_cother (int interactive, struct cmdarg **args)
{
  rp_window *cur, *w;

  cur = current_window();
  w = group_last_window_by_class (rp_current_group, cur->res_class);

  if (!w)
    return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
  else
    set_active_window_force (w);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_iother (int interactive, struct cmdarg **args)
{
  rp_window *cur, *w;

  cur = current_window();
  w = group_last_window_by_class_complement (rp_current_group, cur->res_class);

  if (!w)
    return cmdret_new (MESSAGE_NO_OTHER_WINDOW, RET_FAILURE);
  else
    set_active_window_force (w);

  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_undo (int interactive, struct cmdarg **args)
{
  rp_frame_undo *cur;

  list_first (cur, &rp_frame_undos, node);
  if (!cur)
    return cmdret_new ("No more undo information available", RET_FAILURE);
  else
    {
      cmdret *ret;

      ret = frestore (cur->frames, cur->screen);
      /* Delete the newest node */
      pop_frame_undo (cur);
      return ret;
    }
}

cmdret *
cmd_prompt (int interactive, struct cmdarg **args)
{
  cmdret *ret;
  char *query, *output, *prefix;

  if (interactive)
    return cmdret_new (NULL, RET_FAILURE);

  if (args[0] == NULL)
    output = get_input(MESSAGE_PROMPT_COMMAND, trivial_completions);
  else
    {
      prefix = strchr (ARG_STRING(0), ':');
      if (prefix)
	{
	  prefix++; 		/* Don't return the colon. */
	  query = xmalloc (prefix - ARG_STRING(0) + 1);
	  strncpy (query, ARG_STRING(0), prefix - ARG_STRING(0));
	  query[prefix - ARG_STRING(0)] = 0;	/* null terminate */
	  output = get_more_input (query, prefix, trivial_completions);
	  free (query);
	}
      else
	{
	  output = get_input (ARG_STRING(0), trivial_completions);
	}
    }
  ret = cmdret_new (output, RET_SUCCESS);
  if (output)
    free (output);
  return ret;
}

cmdret *
cmd_describekey (int interactive, struct cmdarg **args)
{
  char *keysym_name;
  rp_action *key_action;
  KeySym keysym;		/* Key pressed */
  unsigned int mod;		/* Modifiers */
  int rat_grabbed = 0;
  rp_keymap *map;

  map = ARG(0,keymap);

  XGrabKeyboard (dpy, current_screen()->key_window, False, GrabModeSync, GrabModeAsync, CurrentTime);

  /* Change the mouse icon to indicate to the user we are waiting for
     more keystrokes */
  if (defaults.wait_for_key_cursor)
    {
      grab_rat();
      rat_grabbed = 1;
    }

  read_key (&keysym, &mod, NULL, 0);
  XUngrabKeyboard (dpy, CurrentTime);

  if (rat_grabbed)
    ungrab_rat();

  if ((key_action = find_keybinding (keysym, x11_mask_to_rp_mask (mod), map)))
    {
      return cmdret_new (key_action->data, RET_SUCCESS);
    }
  else
    {
      cmdret *ret;
      /* No key match, notify user. */
      keysym_name = keysym_to_string (keysym, x11_mask_to_rp_mask (mod));
      ret = cmdret_new_printf (RET_SUCCESS, "describekey: unbound key '%s'", keysym_name);
      free (keysym_name);
      return ret;
    }
}

cmdret *
cmd_dedicate (int interactive, struct cmdarg **args)
{
  rp_frame *f;
  
  f = current_frame();
  if (!f) return cmdret_new (NULL, RET_SUCCESS);

  if (args[0])
    /* Whatever you set it to. */
    f->dedicated = ARG(0,number);
  else
    /* Just toggle it, rather than on or off. */
    f->dedicated = !(f->dedicated);

  return cmdret_new_printf (RET_SUCCESS, "Consider this frame %s.",
			    f->dedicated ? "chaste":"promiscuous");
}

cmdret *
cmd_putsel (int interactive, struct cmdarg **args)
{
  set_selection(ARG_STRING(0));
  return cmdret_new (NULL, RET_SUCCESS);
}

cmdret *
cmd_getsel (int interactive, struct cmdarg **args)
{
  char *sel = get_selection();
  cmdret *ret;
  ret = cmdret_new (sel, RET_SUCCESS);
  free (sel);
  return ret;
}
