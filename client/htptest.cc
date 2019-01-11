#define COMPILE_IT_7

#define BOOST_LOG_DYN_LINK 1

#ifdef COMPILE_IT_1
#include <boost/log/trivial.hpp>

int main(int, char*[])
{
  BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
  BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
  BOOST_LOG_TRIVIAL(info) << "An informational severity message";
  BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
  BOOST_LOG_TRIVIAL(error) << "An error severity message";
  BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";

  return 0;
}

#endif

#ifdef COMPILE_IT_2
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

void init()
{
  logging::add_file_log
  (
    keywords::file_name = "sample_%N.log",
    keywords::rotation_size = 10 * 1024 * 1024,
    keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
    keywords::format = "[%TimeStamp%]: %Message%"
   );
}

int main(int, char*[])
{
  init();
  logging::add_common_attributes();

  using namespace logging::trivial;
  src::severity_logger< severity_level > lg;

  BOOST_LOG_SEV(lg, trace) << "A trace severity message";
  BOOST_LOG_SEV(lg, debug) << "A debug severity message";
  BOOST_LOG_SEV(lg, info) << "An informational severity message";
  BOOST_LOG_SEV(lg, warning) << "A warning severity message";
  BOOST_LOG_SEV(lg, error) << "An error severity message";
  BOOST_LOG_SEV(lg, fatal) << "A fatal severity message";

  return 0;
}
#endif 

#ifdef COMPILE_IT_3
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace trivial = logging::trivial;

void init()
{
  logging::register_simple_formatter_factory<trivial::severity_level, char>("Severity");
  logging::add_file_log
  (
    keywords::file_name = "sample_%N.log",
    keywords::rotation_size = 10 * 1024 * 1024,
    keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
    keywords::format = "[%TimeStamp%] [%ThreadID%] [%Severity%] [%LineID%] %Message%"
   );
}

int main(int, char*[])
{
  init();
  logging::add_common_attributes();

  using namespace logging::trivial;
  src::severity_logger< severity_level > lg;

  BOOST_LOG_SEV(lg, trace) << "A trace severity message";
  BOOST_LOG_SEV(lg, debug) << "A debug severity message";
  BOOST_LOG_SEV(lg, info) << "An informational severity message";
  BOOST_LOG_SEV(lg, warning) << "A warning severity message";
  BOOST_LOG_SEV(lg, error) << "An error severity message";
  BOOST_LOG_SEV(lg, fatal) << "A fatal severity message";

  return 0;
}
#endif 

#ifdef COMPILE_IT_4
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace trivial = logging::trivial;
namespace attrs = boost::log::attributes;

void init()
{
  logging::register_simple_formatter_factory<trivial::severity_level, char>("Severity");
  logging::add_file_log
  (
    keywords::file_name = "sample_%N.log",
    keywords::rotation_size = 10 * 1024 * 1024,
    keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
    keywords::format = "[%TimeStamp%] [%ThreadID%] [%Severity%] [%ProcessID%] [%LineID%] [%MyAttr%] [%CountDown%] %Message%"
   );

  logging::core::get()->add_global_attribute("MyAttr", attrs::constant<int>(42));
  logging::core::get()->add_global_attribute("CountDown", attrs::counter<int>(100, -1));
}

int main(int, char*[])
{
  init();
  logging::add_common_attributes();

  using namespace logging::trivial;
  src::severity_logger< severity_level > lg;

  BOOST_LOG_SEV(lg, trace) << "A trace severity message";
  BOOST_LOG_SEV(lg, debug) << "A debug severity message";
  BOOST_LOG_SEV(lg, info) << "An informational severity message";
  BOOST_LOG_SEV(lg, warning) << "A warning severity message";
  BOOST_LOG_SEV(lg, error) << "An error severity message";
  BOOST_LOG_SEV(lg, fatal) << "A fatal severity message";

  return 0;
}
#endif 

#ifdef COMPILE_IT_5
#include <boost/lockfree/spsc_queue.hpp>
#include <iostream>

using namespace std;
using namespace boost::lockfree;

void test_spsc()
{
  spsc_queue<int, boost::lockfree::capacity<10000> > mints;
  for (int i = 0; i < 10; i++)
    mints.push(i);

  int v, c = 0;;
  while (mints.pop(v))
  {
    c++;
    cout << "pos " << c << " is " << v << endl;
  }
}

int main(int argc, char *argv[])
{
  test_spsc();
  return 0;
}
#endif

#ifdef COMPILE_IT_6

//need lib boost_coroutine for link
#include <iostream>
#include <boost/coroutine/all.hpp>

using namespace std;
typedef boost::coroutines::asymmetric_coroutine< void >::pull_type pull_coro_t;
typedef boost::coroutines::asymmetric_coroutine< void >::push_type push_coro_t;

void foo(push_coro_t & sink)
{
  std::cout << "1";
  sink();
  std::cout << "2";
  sink();
  std::cout << "3";
  sink();
  std::cout << "4";
}

int main(int argc, char * argv[])
{
  {
    pull_coro_t source(foo);
    while (source)
    {
      std::cout << "-";
      source();
    }
  }

  std::cout << "\nDone" << std::endl;

  return 0;
}
#endif

#ifdef COMPILE_IT_7

#include <iostream>
#include <boost/coroutine/all.hpp>

typedef boost::coroutines::asymmetric_coroutine< int >::pull_type pull_coro_t;
typedef boost::coroutines::asymmetric_coroutine< int >::push_type push_coro_t;


void runit(push_coro_t & sink1)
{
  std::cout << "1" << std::endl;
  sink1(10);
  std::cout << "2" << std::endl;
  sink1(20);
  std::cout << "3" << std::endl;
  sink1(30);
  std::cout << "4" << std::endl;
}

int main(int argc, char * argv[])
{
  {
    pull_coro_t source(runit);
    while (source)
    {
      int ret = source.get();
      std::cout << "ret: " << ret << std::endl;
      source();
    }
  }

  std::cout << "\nDone" << std::endl;

  return 0;
}

#endif

#ifdef COMPILE_IT_8
#include <iostream>
#include <boost/coroutine/all.hpp>

typedef boost::coroutines::asymmetric_coroutine< int >::pull_type pull_coro_t;
typedef boost::coroutines::asymmetric_coroutine< int >::push_type push_coro_t;


void runit(pull_coro_t & source)
{
  std::cout << source.get();
  source();
  std::cout << source.get();
  source();
  std::cout << source.get();
  source();
  std::cout << source.get();
}

int main(int argc, char * argv[])
{
  {
    push_coro_t sink(runit);

    int i = 0;
    while (sink)
    {
      ++i;
      sink(i);
      std::cout << "-";
    }
  }

  std::cout << "\nDone" << std::endl;

  return 0;
}
#endif
