#include <stdio.h>
#include <math.h>

main()
{
	int A,B,C,t,h,i,j,k;
	int sum_column,sum_row,diagonal1,diagonal2;
	int conf,diag,seed,max;
	int U[101][101],V[101][101];
	int rand();
	A=1,B=1,C=1;

	printf("Please define the queen problem size(5-100).\n");
	scanf("%d",&max);
	printf("Please input a seed(0-999).\n");
	scanf("%d",&seed);

	for(i=1;i<=seed;i++){ U[1][1]=rand(); };  
	for(i=1;i<=max;i++){
		for(j=1;j<=max;j++){
			U[i][j] = -(abs(rand() % 8));
			V[i][j]=0; }; };

	/* Main program */

	t=0; diag=1; 
        while((diag>0) && (t<500)){
		diag=0;
		for(i=1;i<=max;i++){
			for(j=1;j<=max;j++){
				sum_column=0; 
				sum_row=0;
				for(k=1;k<=max;k++){
					sum_row=sum_row+V[i][k];
					sum_column=sum_column+V[k][j]; }
				diagonal1=0; 
				k=1;
				while(((j+k)<=max) && ((i-k)>=1)){
					diagonal1=diagonal1+V[i-k][j+k];
					k++; }
				k=1;
				while(((j-k)>=1) && ((i+k)<=max)){
					diagonal1=diagonal1+V[i+k][j-k];
					k++; }
				diagonal2=0,k=1;
				while(((j+k)<=max) && ((i+k)<=max)){
					diagonal2=diagonal2+V[i+k][j+k];
					k++; }
				k=1;
				while(((j-k)>=1) && ((i-k)>=1)){
					diagonal2=diagonal2+V[i-k][j-k];
					k++; }
				h=0; conf=1;
				if(sum_column == 0) h=1;
				if(sum_row == 0) h++;
				if((sum_column+sum_row==2) && (diagonal1<2) && (diagonal2<2))
					conf=0;
				U[i][j]=U[i][j]-A*(sum_row+sum_column-2)-B*(diagonal1+diagonal2)+C*h;
				if(U[i][j]>8) U[i][j]=8;
				if(U[i][j]<-8) U[i][j]=-8;

				if(U[i][j]>0) V[i][j]=1;
				else V[i][j]=0;

				diag=diag+conf;
			};
		};
		t++;
		printf("t=%d\n",t);
		if((t % 18) < 9)
		{
			C=4;
		}
		else
		{
			C=1;
		};

	printf("the number of iteration steps=%d\n",t);
	printf("\n");
	for(i=1;i<=max;i++){
		for(j=1;j<=max;j++){
			if(j==max){
				if(V[i][j]==1)
					printf("*\n");
				else
					printf("-\n");
			}
			else{
				if(V[i][j]==1)
					printf("* ");
				else
					printf("- ");
			}
		}
	}
}
