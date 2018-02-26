//return a pointer to the first substr match
#include <string.h>
#include <stdio.h>

void *mymemmem(const void *haystack, size_t n1, const void *needle, size_t n2) {
    const unsigned char *p1 = haystack;
    const unsigned char *p2 = needle;

    if (n2 == 0)
        return (void*)p1;
    if (n2 > n1)
        return NULL;

    for (const unsigned char *p = p1; p < p1+n1; p++) {
	if (*p == *p2) {
        	if (!memcmp(p, p2, n2))
            		return (void*)p;
	}
    }

    return NULL;
}
/*
int main (int argc, char *argv[])
{
	int i;
	char sstr[16];
	char mstr[1000];
	char *found;
	void *found2;

	printf("size of charp %u size of void p %u\n", sizeof(found), sizeof(found2));
	if (argc !=2) {
		printf("no params passed\n");
		return 0;
	}
	else{
		if(!argv[1]){
			printf("Null str passed\n");
			return 0;
		}
		strcpy(sstr, argv[1]);
		printf("passed string len %d or %d\n", strlen(sstr), strlen(argv[1]));
	}
		
	strcpy(&(mstr[40]), "bleak");
	for (i=50; i<1000; i++)
		mstr[i] = i%256;

	printf("haystack len %d needle len %d\n", sizeof(mstr), strlen(sstr));

	found = mymemmem(mstr, sizeof(mstr), sstr, strlen(sstr));
	printf("mmstr %llx  found %llx sstr %llx size %d\n", mstr, found, sstr);

	if(!found) {
		printf("no match\n");
		return 0;
	}
	else if(found == mstr)
		return 0;
	else
		printf ("%.*s\n", strlen(sstr), found);

}
*/
