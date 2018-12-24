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


/*
install boost to /usr/lib64/boost
add lib path and link lib in client/CMakeLists.txt
export LD_LIBRARY_PATH=/usr/lib64/boost/lib/
*/
#define BOOST_LOG_DYN_LINK 1
#include <boost/log/trivial.hpp>

void test_log()
{
  BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
  BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
  BOOST_LOG_TRIVIAL(info) << "An informational severity message";
  BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
  BOOST_LOG_TRIVIAL(error) << "An error severity message";
  BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";
}

int main(int argc, char *argv[])
{
  test_log();
  return 0;
}

