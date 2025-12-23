//Using https://godbolt.org/ 
// Set -m32 -O0 and -m32 -O3 to see the difference in assembly output

//EX0
int square(int x, int y) {
  int result = x;
  result += y;
  return result;
}

//EX1

int square(int num) {
    int a = num;
    int b = num;
    int mult = a * b;
    return mult;
}

//EX2 

int square(int num) {
    int a = num;       
    int x,y,k,z;
    z = 3;
    y = 1;
    x = 5;
    k = 1;
    return a * a;

}


//EX3

void foo(int bar, int baz) {
    // some code
}


int square(int num) {
    int a = num;
    int x,y,k,z;
    z = 3;
    y = 1;
    foo(123,456);
    x = 5;
    k = 1;
    return a * a;

}