int inc(int i) { return i + 1; }

int dec(int i) { return i - 1; }

int (*fptr)(int) = &inc;

void switchfptr()
{
  if (fptr == inc) {
    fptr = &dec;
  } else {
    fptr = &inc;
  }
}

int main(void)
{
  int i = 0;
  i = inc(i);
  i = dec(i);

  for (int i = 0; i < 5; i++) {
    i = fptr(i);
    switchfptr();
  }

  return i;
}
