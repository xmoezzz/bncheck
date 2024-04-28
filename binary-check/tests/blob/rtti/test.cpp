#include <iostream>
#include <typeinfo>

class A
{
public:
  virtual ~A () { }
};

class B : public A
{
};

void rtti_test (A& a)
{
  try
    {
      B& b = dynamic_cast<B&> (a);
    } 
  catch (std::bad_cast)
    {
      std::cout << "Invalid cast.\n";
    }
  std::cout << "rtti is enabled in this compiler.\n";
}

int
main ()
{
  A *a1 = new B;
  rtti_test (*a1);  //valid cast
  return 0;
}