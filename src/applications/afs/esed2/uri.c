/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file applications/afs/module/uri.c 
 * @brief Parses and produces uri strings.
 * @author Igor Wronsky
 *
 * What spaghetti ...
 *
 * How it works: first parse all tag/value pairs into a table. Take
 * note of the "action" type. Then call a specific parser to create 
 * the actual data structure.
 *
 * Bugs: leaks mem if some tags except keyword or numeric tags
 * are specified more than once.
 *
 **/

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define GOT_FILENAME 	(1L<<0)
#define GOT_NS          (1L<<1)
#define GOT_QH          (1L<<2)
#define GOT_KH          (1L<<3)
#define GOT_KEYWORD     (1L<<4)
#define GOT_SIZE        (1L<<5)
#define GOT_CRC         (1L<<6)
#define GOT_PSEUDONYM   (1L<<7)
#define GOT_PASSWORD    (1L<<8)

/* internal struct for tag/value pairs */
typedef struct {
  char * tag;
  char * value;
} tagTable;

/* case-specific helper functions */
static int parseDownloadURI(tagTable * tags,
	 	            int tagcount,
 		            generalURI ** block);
static int parseSearchURI(tagTable * tags,
                          int tagcount,
		          generalURI ** block);
static int parseInsertURI(tagTable * tags,
                          int tagcount,
		          generalURI ** block);
static int parseDeleteURI(tagTable * tags,
                          int tagcount,
		          generalURI ** block);

/**
 * Parses an AFS URI string to internal representation
 *
 * Usage:
 *   generalURI * block;
 *   parseURI(string, &block);
 *   if(block->action == URI_ACTION_DOWNLOAD) {
 *     downloadURI * bl;
 *     bl = (downloadURI *)block;
 *   ...
 *
 * @param uri an uri string
 * @param block output, the parsed values
 * @returns SYSERR on failure
 **/
int parseURI(char * uri,
	     generalURI ** block) 
{
  char * scratch;
  char * name;
  char * uptr;
  char * sptr;
  char * nptr;
  int action;
  tagTable * tags = NULL;
  int tagcount = 0;
  int ret = SYSERR;

  if( uri == NULL || 
      strlen(uri) < strlen(AFS_URI_PREFIX) ||
      strncmp(uri, AFS_URI_PREFIX, strlen(AFS_URI_PREFIX)) !=0 )
    return SYSERR;

  scratch = MALLOC(strlen(uri));
 
  /* parse action */
  uptr = &uri[strlen(AFS_URI_PREFIX)];
  sptr = scratch;
  while(*uptr!='/' && *uptr!=0)
    *sptr++=*uptr++;
  *sptr = 0;
  if(*uptr == 0) {
     LOG(LOG_ERROR,
     	 "ERROR: Premature end of URI\n");
     FREE(scratch);
     return SYSERR;
  }
  uptr++;
  
  if(strcmp(scratch,"download") == 0)
    action = URI_ACTION_DOWNLOAD;
  else if(strcmp(scratch,"search") == 0)
    action = URI_ACTION_SEARCH;
  else if(strcmp(scratch,"insert") == 0)
    action = URI_ACTION_INSERT;
  else if(strcmp(scratch,"delete") == 0)
    action = URI_ACTION_DELETE;
  else {
    LOG(LOG_ERROR,
    	"ERROR: Unknown action in %s\n", scratch);
    FREE(scratch);
    return SYSERR;
  }

  /* parse all tags to a tagTable */
  name = MALLOC(strlen(uri));
  while(*uptr != 0) {
    nptr = name;

    /* get the tag */
    while(*uptr != '=' && *uptr != 0)
      *nptr++=*uptr++;
    *nptr=0;
    if(*uptr==0) {
      FREE(scratch);
      FREE(name);
      LOG(LOG_ERROR,
      	  "ERROR: Premature end of tag/name pair (1)\n");
      return SYSERR;
    }
    uptr++;
    
    /* get the value */
    sptr = scratch;
    while(*uptr != '?' && *uptr != 0)
      *sptr++=*uptr++;
    *sptr=0;
    if(sptr == scratch) {
      LOG(LOG_ERROR,
	  "ERROR: Missing value for tag %s\n", name);
      FREE(scratch);
      FREE(name);
      return SYSERR;
    }

    GROW(tags,
         tagcount,
	 tagcount+1);
    tags[tagcount-1].tag = STRDUP(name);
    tags[tagcount-1].value = STRDUP(scratch);
    
    if(*uptr==0)
      break;
    else
      uptr++;
  }
  
  FREE(name);
  FREE(scratch);

  switch(action) {
    case URI_ACTION_DOWNLOAD:
      ret = parseDownloadURI(tags,tagcount,block);
      break;
    case URI_ACTION_SEARCH:
      ret = parseSearchURI(tags,tagcount,block);
      break;
    case URI_ACTION_INSERT:
      ret = parseInsertURI(tags,tagcount,block);
      break;
    case URI_ACTION_DELETE:
      ret = parseDeleteURI(tags,tagcount,block);
      break;
    default:
      break;
  }

  FREE(tags);
  
  return ret;
}

static int parseDownloadURI(tagTable * tags,
  		            int tagcount,
		            generalURI ** block) {
    int i;
    int gotmask=0;
    char * tag;
    char * value;
    downloadURI * ret;

    ret = MALLOC(sizeof(downloadURI));
    ret->action = URI_ACTION_DOWNLOAD;

    for(i=0;i<tagcount;i++) {
      tag=tags[i].tag;
      value=tags[i].value;

      if(strcmp(tag, "filename") == 0) {
        ret->filename = STRDUP(value);
	gotmask |= GOT_FILENAME;
      }
      else if(strcmp(tag, "kh") == 0) {
        hex2hash((HexName*)value,
                 &ret->fid.chk.key);
	gotmask |= GOT_KH;
      }
      else if(strcmp(tag, "qh") == 0) {
        hex2hash((HexName*)value,
                 &ret->fid.chk.query);
	gotmask |= GOT_QH;
      }
      else if(strcmp(tag, "size") == 0) {
	unsigned int sval;
        sscanf(value, 
	       "%u", 
	       &sval);
	ret->fid.file_length = (unsigned int) htonl(sval);
	gotmask |= GOT_SIZE;
      }
      else if(strcmp(tag, "crc") == 0) {
        sscanf(value, "%X", &ret->fid.crc);
	ret->fid.crc = htonl(ret->fid.crc);
	gotmask |= GOT_CRC;
      }
      else {
        LOG(LOG_WARNING,
      	    "WARNING: Unknown tag %s in download context\n", 
	    tag);
      }
    } 
 
    if(! (gotmask & GOT_CRC) ||
       ! (gotmask & GOT_KH) ||
       ! (gotmask & GOT_QH) ||
       ! (gotmask & GOT_SIZE) ) {
      LOG(LOG_ERROR,
      	  "ERROR: Insufficient tags for download\n");
      FREE(ret);
      return SYSERR;
    }

    *block = (generalURI *)ret;

    return OK;
}

static int parseSearchURI(tagTable * tags,
 	  	          int tagcount,
		          generalURI ** block) {
    int i;
    int gotmask=0;
    char * tag;
    char * value;
    searchURI * ret;

    ret = MALLOC(sizeof(searchURI));
    ret->action = URI_ACTION_SEARCH;

    for(i=0;i<tagcount;i++) {
      tag = tags[i].tag;
      value = tags[i].value;

      if(strcmp(tag, "namespace") == 0) {
        ret->namespace = MALLOC(sizeof(HashCode160));
        if (SYSERR == tryhex2hash(value,
      		  		  ret->namespace)) {
          LOG(LOG_ERROR,
              "ERROR: namespace is not in HEX format\n");
	  return SYSERR;
        }
	gotmask |= GOT_NS;
      }
      /* namespace keyhash identifier */
      /* FIXME: either keywords or kh is redundant */
      else if(strcmp(tag, "kh") == 0) {
        ret->keyhash = MALLOC(sizeof(HashCode160));
        if (SYSERR == tryhex2hash(value,
        		          ret->keyhash)) {
          LOG(LOG_DEBUG,
              "DEBUG: namespace ID is not in HEX format, using hash of ASCII text (%s).\n",
	      value);
  	  hash(value, strlen(value), ret->keyhash);
        }
        gotmask |= GOT_KH;
      }
      else if(strcmp(tag, "keyword") == 0) {
        GROW(ret->keywords,
      	     ret->keycount,
	     ret->keycount+1);
        ret->keywords[ret->keycount-1] = STRDUP(value);
	gotmask |= GOT_KEYWORD;
      }
      else {
        LOG(LOG_WARNING,
      	    "WARNING: Unknown tag name %s in search context\n", 
	    tag);
      }
    }
  
    if(! (gotmask & GOT_KEYWORD) ) {
      LOG(LOG_ERROR,
      	  "ERROR: Insufficient tags for search\n");
      FREE(ret);
      return SYSERR;
    }

    *block = (generalURI *)ret;

    return OK;
}

static int parseInsertURI(tagTable * tags,
 	  	          int tagcount,
		          generalURI ** block) {
    int i;
    int gotmask=0;
    char * tag;
    char * value;
    insertURI * ret;

    ret = MALLOC(sizeof(insertURI));
    ret->action = URI_ACTION_INSERT;

    for(i=0;i<tagcount;i++) {
      tag = tags[i].tag;
      value = tags[i].value;

      if(strcmp(tag, "filename") == 0) {
        ret->filename = STRDUP(value);
 	gotmask |= GOT_FILENAME;
      }
      else if(strcmp(tag, "pseudonym") == 0) {
        ret->pseudonym = STRDUP(value);
        gotmask |= GOT_PSEUDONYM;
      }
      else if(strcmp(tag, "password") == 0) {
        ret->password = STRDUP(value);
        gotmask |= GOT_PASSWORD;
      } 
      else {
        LOG(LOG_WARNING,
      	    "WARNING: Unknown tag name %s in search context\n", 
	    tag);
      }
    }
  
    if(! (gotmask & GOT_FILENAME) ) {
      LOG(LOG_ERROR,
     	  "ERROR: Insufficient tags for insert\n");
      FREE(ret);
      return SYSERR;
    }

    *block = (generalURI *)ret;

    return OK;
}

static int parseDeleteURI(tagTable * tags,
 	  	          int tagcount,
		          generalURI ** block) {
    int i;
    int gotmask=0;
    char * tag;
    char * value;
    deleteURI * ret;

    ret = MALLOC(sizeof(insertURI));
    ret->action = URI_ACTION_DELETE;

    for(i=0;i<tagcount;i++) {
      tag = tags[i].tag;
      value = tags[i].value;

      if(strcmp(tag, "filename") == 0) {
        ret->filename=STRDUP(value);
 	gotmask |= GOT_FILENAME;
      }
      else {
        LOG(LOG_WARNING,
      	    "WARNING: Unknown tag name %s in search context\n", 
	    tag);
      }
    }
  
  if(! (gotmask & GOT_FILENAME) ) {
    LOG(LOG_ERROR,
    	"ERROR: Insufficient tags for delete\n");
    FREE(ret);
    return SYSERR;
  }

  *block = (generalURI *)ret;

  return OK;
}

/**
 * Turns an internal representation into an AFS uri string
 *
 * @param block the values to print
 * @param uri, output
 * @returns SYSERR on failure
 **/
int produceURI(generalURI * block,
               char ** uri)
{
  HexName hex;
  char scratch[512];
  char * resptr;
  int i;

  if(!block) {
    LOG(LOG_ERROR,
        "ERROR: NULL block passed to produceURI()");
    return SYSERR;
  }
  
  *uri = MALLOC(1024);
  resptr = *uri;
  *resptr = 0;
  strcat(resptr, AFS_URI_PREFIX);

  switch(block->action) {
    case URI_ACTION_DOWNLOAD:
    {
      downloadURI * bl;
      
      bl = (downloadURI *)block;
      strcat(resptr, "download/");
      hash2hex(&bl->fid.chk.key,
               &hex);
      sprintf(scratch, "kh=%s?", (char*)&hex);
      strcat(resptr, scratch);
      hash2hex(&bl->fid.chk.query,
      	       &hex);
      sprintf(scratch, "qh=%s?", (char*)&hex);
      strcat(resptr, scratch);
      sprintf(scratch, 
	      "size=%u?crc=%X?", 
              (unsigned int) ntohl(bl->fid.file_length),
              (unsigned int) ntohl(bl->fid.crc));
      strcat(resptr, scratch);
      if(bl->filename != NULL) {
        strcat(resptr,bl->filename);
        strcat(resptr, "?");
      }
    }
    break;
    case URI_ACTION_SEARCH:
    {
      searchURI * bl;
      
      bl = (searchURI *)block;
      strcat(resptr, "search/");
      if(bl->namespace != NULL) {
         hash2hex(bl->namespace, 
                  &hex);
         sprintf(scratch, "ns=%s?", (char*)&hex);
         strcat(resptr, scratch);
      }
      if(bl->keyhash != NULL) {
         hash2hex(bl->keyhash,
    	          &hex);
        sprintf(scratch, "kh=%s?", (char*)&hex);
        strcat(resptr, scratch);
      }
      for(i=0;i<bl->keycount;i++) {
        sprintf(scratch, "keyword=%s?", bl->keywords[i]);
        strcat(resptr,scratch);
      }    
    }
    break;
    case URI_ACTION_INSERT:
    {
      insertURI * bl;
      
      bl = (insertURI *)block;
      strcat(resptr, "insert/");
      if(bl->filename != NULL) {
        strcat(resptr,bl->filename);
        strcat(resptr, "?");
      }
    }
    break;
    case URI_ACTION_DELETE:
    {
      deleteURI * bl;
      
      bl = (deleteURI *)block;
      strcat(resptr, "delete/");
      if(bl->filename != NULL) {
        strcat(resptr,bl->filename);
        strcat(resptr, "?");
      }
    } 
    break;
    default:
      FREE(*uri);
      LOG(LOG_ERROR,
      	  "ERROR: Unknown action %d\n", block->action);
      return SYSERR;
    break;
  }
 
  if(resptr[strlen(resptr)-1]=='?')
    resptr[strlen(resptr)-1]=0;

  return OK;
}

/* end of uri.c */

