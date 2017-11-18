#define MAX_LENGTH_PACKET 120000
#define LINE_LENGTH 16

#include<netinet/in.h>
#include<time.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<ncurses.h>
#include<stdlib.h>
#include<string.h>

#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

void check_packet(char*, int, WINDOW *);

typedef struct  s_list {
  char          *data;
  char          *packet;
  int           select;
  struct tm     *timeinfo;
  int           size;
  struct s_list *next;
  struct s_list *prev;
}               t_list;

void delete_elem(t_list *list) {
  t_list  *tmp;

  tmp = list->next;
  tmp->next->prev = list;
  list->next = tmp->next;
  free(tmp->data);
  free(tmp);
}

int list_len(t_list *list) {
  t_list  *tmp;
  int i;

  if (!list)
    return (0);
  i = 1;
  tmp = list->next;
  while (tmp && tmp != list) {
    tmp = tmp->next;
    i++;
  }
  return (i);
}

void print_line(WINDOW *win, t_list *elem, int i, int pos) {
  wclrtoeol(win);
  if (i == pos) {
    wattron(win, A_REVERSE);
    mvwprintw(win, i, 1, "%s", asctime(elem->timeinfo));
    wattroff(win, A_REVERSE);
  } else {
    mvwprintw(win, i, 1, "%s", asctime(elem->timeinfo));
  }
  wrefresh(win);
}

void print_top_screen(WINDOW *win, t_list **list, int pos, int key) {
  int i;
  t_list  *tmp;

  if (key == KEY_DOWN && pos == LINES / 2 - 1)
    *list = (*list)->next;
  tmp = *list;
  i = 1;
  print_line(win, tmp, i, pos);
  tmp = tmp->next;
  while (i < LINES / 2 - 1 && tmp != *list) {
    print_line(win, tmp, i++, pos);
    tmp = tmp->next;
  }
}

void cursor(WINDOW *haut, WINDOW *bas, t_list **list, int key) {
  static int  pos = -42;

  if (pos == -42)
    pos = LINES / 2 - 2;
  (*list)->select = 0;
  if (key == KEY_UP) {
    pos = (pos - 1);
    if (pos <= 0) {
      (*list) = (*list)->prev;
      pos = 1;
    }
  } else if (key == KEY_DOWN) {
    pos = (pos + 1) % (LINES / 2 - 1);
    if (pos == 0) {
      pos = LINES / 2 - 2;
      (*list) = (*list)->next;
    }
  }
  (*list)->select = 1;
  print_top_screen(haut, list, pos, key);
  check_packet((*list)->data, (*list)->size, bas);
}

void add_line(char *buffer, int size, t_list **list) {
  t_list  *elem;
  time_t rawtime;
  int len;

  len = list_len(*list);
  if (!(elem = malloc(sizeof(t_list)))) {
    printf("%s\n", "Error Malloc");
    exit(1);
  }

  time(&rawtime);
  elem->timeinfo = localtime(&rawtime);
  elem->data = buffer;
  elem->size = size;
  if (!(*list)) {
    elem->select = 1;
    elem->next = elem;
    elem->prev = elem;
  } else {
    elem->select = 0;
    elem->next = (*list)->next;
    elem->prev = *list;
    (*list)->next->prev = elem;
    (*list)->next = elem;
  }
  *list = elem;
}

void capture_packet(int raw_socket, t_list **list) {
  int data_size;
  struct sockaddr socket_addr;
  int sockaddr_size = sizeof(socket_addr);
  int i = 0;

  char *buffer = malloc(sizeof(char *) * MAX_LENGTH_PACKET);
  while (i < 1) {
    data_size = recvfrom(raw_socket, buffer, MAX_LENGTH_PACKET, 0, &socket_addr, (socklen_t*)&sockaddr_size);
    if (data_size < 0) {
      printf("Recvfrom error\n");
      exit(1);
    }
    i++;
    add_line(buffer, data_size, list);
  }
}

int main(void) {
  WINDOW *haut, *bas;
  t_list  *list = NULL;
  char buf[100];
  int i;
  int highlight = 1;
  int choice = 0;
  int c;

  int data_size;
  int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  struct sockaddr socket_addr;
  int sockaddr_size = sizeof(socket_addr);

  if(raw_socket < 0){
    perror("Socket Error");
    exit(1);
  }
  char *buffer = malloc(sizeof(char *) * MAX_LENGTH_PACKET);
  initscr();
  clear();
  noecho();
  cbreak();
  haut = subwin(stdscr, LINES / 2, COLS, 0, 0);
  bas = subwin(stdscr, LINES / 2, COLS, LINES / 2, 0);

  keypad(haut, TRUE);
  box(haut, ACS_VLINE, ACS_HLINE);
  box(bas, ACS_VLINE, ACS_HLINE);

  while (1) {
    timeout(300);
    c = wgetch(haut);
    switch(c) {
      case KEY_UP:
        cursor(haut, bas, &list, KEY_UP);
        break;
      case KEY_DOWN:
        cursor(haut, bas, &list, KEY_DOWN);
        break;
    }
    capture_packet(raw_socket, &list);
  }
  close(raw_socket);

  mvwprintw(bas, 1, 1, "Ceci est la fenetre du bas");

  wrefresh(bas);

  getch();
  endwin();

  return 0;
}
