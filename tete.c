struct toto {
  char  **toto;
};

int main(int argc, char *argv[]) {
  struct toto var;

  var.toto = argv;
  printf("%s\n", var.toto[3]);
}
