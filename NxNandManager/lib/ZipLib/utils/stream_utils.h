#pragma once
#include "../../../res/progress_info.h"
#include <iostream>
#include <vector>

namespace utils { namespace stream {

static void copy(std::istream& from, std::ostream& to, size_t bufferSize = 1024 * 1024, void(*updateProgress)(ProgressInfo) = nullptr, ProgressInfo *pi = nullptr)
{
  std::vector<char> buff(bufferSize);  

  if (updateProgress != nullptr)
  {
      pi->bytesCount = 0;
      updateProgress(*pi);
  }
  do
  {
    from.read(buff.data(), buff.size());
    to.write(buff.data(), from.gcount());

    if (updateProgress != nullptr && static_cast<size_t>(from.gcount()) == buff.size())
    {
        pi->bytesCount += static_cast<size_t>(from.gcount());
        updateProgress(*pi);
    }

  } while (static_cast<size_t>(from.gcount()) == buff.size());
    int end = 0;
}

} }
