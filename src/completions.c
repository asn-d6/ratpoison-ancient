#include <string.h>

#include "ratpoison.h"
#include "completions.h"

rp_completions *
completions_new (completion_fn list_fn)
{
  rp_completions *c;

  c = (rp_completions *) xmalloc (sizeof(rp_completions));

  INIT_LIST_HEAD (&c->completion_list);
  c->complete_fn = list_fn;
  c->last_match = NULL;
  c->partial = NULL;
  c->virgin = 1;
  
  return c;
}

void
completions_free (rp_completions *c)
{
  struct sbuf *cur;
  struct list_head *tmp, *iter;

  /* Clear our list */
  list_for_each_safe_entry (cur, iter, tmp, &c->completion_list, node)
    {
      list_del (&cur->node);
      sbuf_free (cur);
    }

  /* Free the partial string. */
  if (c->partial)
    free (c->partial);
}

void
completions_assign (rp_completions *c, struct list_head *new_list)
{
  struct sbuf *cur;
  struct list_head *tmp, *iter;

  /* Clear our list */
  list_for_each_safe_entry (cur, iter, tmp, &c->completion_list, node)
    {
      list_del (&cur->node);
      sbuf_free (cur);
    }

  /* splice the list into completion_list. Note that we SHOULDN'T free
     new_list, because they share the same memory. */
  INIT_LIST_HEAD (&c->completion_list);
  list_splice (new_list, &c->completion_list);

  list_first (c->last_match, &c->completion_list, node);
}

void
completions_update (rp_completions *c, char *partial)
{
  struct list_head *new_list;

  new_list = c->complete_fn (partial);

  c->virgin = 0;
  if (c->partial)
    free (c->partial);
  c->partial = xstrdup (partial);

  completions_assign (c, new_list);

  /* Free the head structure for our list. */
  free (new_list);
}

/* Return a completed string that starts with partial. */
char *
completions_next_completion (rp_completions *c, char *partial)
{
  struct sbuf *cur;

  if (c->virgin)
    {
      completions_update (c, partial);
      
      /* Since it's never been completed on and c->last_match points
	 to the first element of the list which may be a match. So
	 check it. FIXME: This is a bit of a hack. */
      if (c->last_match == NULL)
	return NULL;

      if (str_comp (sbuf_get (c->last_match), c->partial, strlen (c->partial)))
	return sbuf_get (c->last_match);
    }

  if (c->last_match == NULL)
    return NULL;

  /*  */

  /* search forward from our last match through the list looking for
     another match. */
  for (cur = list_next_entry (c->last_match, &c->completion_list, node);
       cur != c->last_match;
       cur = list_next_entry (cur, &c->completion_list, node))
    {
      if (str_comp (sbuf_get (cur), c->partial, strlen (c->partial)))
	{
	  /* We found a match so update our last_match pointer and
	     return the string. */
	  c->last_match = cur;
	  return sbuf_get (cur);
	}
    }

  return NULL;
}
