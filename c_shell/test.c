abc()
{
  printf("hoge\n");
}

int (*ret(void))()
{
  return abc;
}

main()
{
    int (*creat_func)();
    creat_func = ret();
    creat_func();
    ret()();
}
