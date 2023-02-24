#include <stdio.h>
#include <sys/utsname.h>

int main() {
   struct utsname unameData;
   int result = uname(&unameData);
   if (result != 0) {
      printf("Failed to get system information.\n");
      return 1;
   }
   printf("Kernel name: %s\n", unameData.sysname);
   printf("Kernel release: %s\n", unameData.release);
   printf("Distribution: %s\n", unameData.version);
   return 0;
}
