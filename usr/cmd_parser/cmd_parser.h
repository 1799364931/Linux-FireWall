
#ifndef _CMD_PARSER_H
#define _CMD_PARSER_H

#include "cmdline.h"

class cmd_parser {

public:
  cmd_parser() {}

  cmdline::parser &get_parser() { return this->parser_; }

private:
  void build_parser() {}

  cmdline::parser parser_;
};

#endif