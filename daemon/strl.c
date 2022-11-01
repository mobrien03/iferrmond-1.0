/******************************************************************************

 Functions strlcpy and strlcat from:

 Secure Programming Cookbook for C and C++, by John Viega, Matt Messier,
 ISBN: 9780596003944, Released July 2003,
 Publisher(s): O'Reilly Media, Inc

 The following applies to example files from material published by O’Reilly 
 Media, Inc. Content from other publishers may include different rules of 
 usage. Please refer to any additional usage rights explained in the actual 
 example files or refer to the publisher’s website.

 O'Reilly books are here to help you get your job done. In general, you may use
 the code in O'Reilly books in your programs and documentation. You do not need
 to contact us for permission unless you're reproducing a significant portion 
 of the code. For example, writing a program that uses several chunks of code 
 from our books does not require permission. Answering a question by citing our
 books and quoting example code does not require permission. On the other hand,
 selling or distributing a CD-ROM of examples from O'Reilly books does require 
 permission. Incorporating a significant amount of example code from our books
 into your product's documentation does require permission.

******************************************************************************/
#include <sys/types.h>
#include <string.h>

/* Function Prototypes */
size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t len);

size_t strlcpy(char *dst, const char *src, size_t size) {
  char       *dstptr = dst;
  size_t     tocopy  = size;
  const char *srcptr = src;

  if (tocopy && --tocopy) {
    do {
      if (!(*dstptr++ = *srcptr++)) break;
    } while (--tocopy);
  }
  if (!tocopy) {
    if (size) *dstptr = 0;
    while (*srcptr++);
  }

  return (srcptr - src - 1);
}

size_t strlcat(char *dst, const char *src, size_t len) {
  char       *dstptr = dst;
  size_t     dstlen, tocopy;
  const char *srcptr = src;

  while (tocopy-- && *dstptr) dstptr++;
  dstlen = dstptr - dst;
  if (!(tocopy = len - dstlen)) return (dstlen + strlen(src));
  while (*srcptr) {
    if (tocopy != 1) {
      *dstptr++ = *srcptr;
      tocopy--;
    }
    srcptr++;
  }
  *dstptr = 0;

  return (dstlen + (srcptr - src));
}
