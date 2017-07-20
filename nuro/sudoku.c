/*
 * SUDOKU Solver
 * Written by Akira KANAI<kanai@sfc.wide.ad.jp>.
 * $Id: sudoku.c,v 1.8 2007/10/23 08:42:01 kanai Exp $
 *
 * Compile:
 * gcc -Wall -O9 -static -o sudoku sudoku.c -lm
 *
 */

/*
 * How to use?
 * 
 * You parepare question file.
 * ./sudoku question.filenae
 *
 * Question File Format:
 *
 * 650030074
 * 900070001
 * 000809000
 * 003010500
 * 510703028
 * 004050600
 * 000305000
 * 400080009
 * 370090052
 *
 * means
 *
 * +-----+-----+-----+
 * |6 5 0|0 3 0|0 7 4+
 * |9 0 0|0 7 0|0 0 1+
 * |0 0 0|8 0 9|0 0 0+
 * +-----+-----+-----+
 * |0 0 3|0 1 0|5 0 0+
 * |5 1 0|7 0 3|0 2 8+
 * |0 0 4|0 5 0|6 0 0+
 * +-----+-----+-----+
 * |0 0 0|3 0 5|0 0 0+
 * |4 0 0|0 8 0|0 0 9+
 * |3 7 0|0 9 0|0 5 2+
 * +-----+-----+-----+
 */

/*
 * MEMO: Internal Structure
 *      0     1     2
 *   +-----+-----+-----+
 *   |0 0 0|0 0 0|0 0 0+
 * 0 |0 0 0|0 0 0|0 0 0+
 *   |0 0 0|0 0 0|0 0 0+
 *   +-----+-----+-----+
 *   |0 0 0|0 0 0|0 0 0+
 * 1 |0 0 0|0 0 0|0 0 0+
 *   |0 0 0|0 0 0|0 0 0+
 *   +-----+-----+-----+
 *   |0 0 0|0 0 0|0 0 0+
 * 2 |0 0 0|0 0 0|0 0 0+
 *   |0 0 0|0 0 0|0 0 0+
 *   +-----+-----+-----+
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>

#define MAX_PHASE 100000
#define MAX_LIMIT 8
#define NUM_1 1
#define NUM_2 1
#define NUM_3 1
#define NUM_3_2 4

	int resultmap[9][9];
  int V[9][9][9];
  int Vm[9][9][9];

void disp(void)
{
  int x, y, z; 

  /* Mapping V to resultmap for disp_result */
  for(x = 0; x < 9; x++)
    {
      for(y = 0; y < 9; y++)
	{
	  resultmap[x][y] = 0;
	  for(z = 0; z < 9; z++)
	    {
	      if(V[x][y][z] == 1)
		{
		  resultmap[x][y] = z + 1;
		}
	    }
	}
    }

  /* Display Result */
  for(y = 0; y < 9; y++)
    {
      if(y % 3 == 0)
	{
	  printf("+-----+-----+-----+\n");
	}
      for(x = 0; x < 9; x++)
	{
	  if(x % 3 == 0)
	    {
	      printf("|%d", resultmap[x][y]);
	    }
	  else
	    {
	      printf(" %d", resultmap[x][y]);
	    }
	}
      printf("+\n");
    }
  printf("+-----+-----+-----+\n");
}

int main(int argc, char **argv)
{
  int U[9][9][9];
  int x, y, z; 
  int h; /* Unknown Var */
  int conf; /* Unknown Var */
  int i; /* Loop Counter */
  int j; /* Loop Counter */
  int k; /* Loop Counter */
  int l; /* Loop Counter */
  int m; /* Loop¡Counter */
  int sum_x, sum_y, sum_z;
  int sum_area;
  int is_area;
  int sum_area_num;
  int var_1, var_2, var_3;
  int diag;
  int phase_count;
  int fd;
  int flag;
  char c[1];
  int n;

  /* init */
  var_1 = NUM_1;
  var_2 = NUM_2;
  var_3 = NUM_3;
  phase_count = 0;
  diag = 1;
  srand((unsigned) time(NULL));
  for(x = 0; x < 9; x++)
    {
      for(y = 0; y < 9; y++)
	{
	  for(z = 0; z < 9; z++)
	    {
	      U[x][y][z] = -(abs(rand() % MAX_LIMIT));
	      V[x][y][z] = 0;
	      Vm[x][y][z] = 0;
	    }
	}
    }


  /* Read From File */
  if( argc < 2)
    {
      exit(1);
    }
  if( (fd = open(argv[1], O_RDONLY) ) < 0){
    perror("open");
    exit(1);
  } 
  for(y = 0; y < 9; y ++){
    for(x = 0; x < 9; x ++){
      *c = 0x00;
      while(*c < 0x30 || *c > 0x39)
	{
	  read(fd, c, 1);
	}
      n = *c - 0x30;
      if(n != 0){
	V[x][y][n - 1] = 1;
	Vm[x][y][n - 1] = 1;
      }
      //printf("set(%d,%d) = %d\n", x, y, n);
    }
  }


  disp();

  while( (diag > 0) && (phase_count < MAX_PHASE) )
    {
      if(phase_count % 1000 == 0){
	printf("Phase:%d\n", phase_count);
      }

      diag = 0;
      for(x = 0; x < 9; x++)
  	{
	  for(y = 0; y < 9; y++)
	    {
	      for(z = 0; z < 9; z++)
		{
		  /* Check Master */
		  flag = (0 == 0);
		  for(i = 0; i < 9; i++)
		    {
		      if(Vm[i][y][z] == 1)
			{
			  flag = flag && (0 != 0);
			}
		      if(Vm[x][i][z] == 1)
			{
			  flag = flag && (0 != 0);
			}
		      if(Vm[x][y][i] == 1)
			{
			  flag = flag && (0 != 0);
			}
		      for(j = 0; j < 3; j++)
			{
			  for(k = 0; k < 3; k++)
			    {
			      if(Vm[ ( ( (x - (x % 3)) / 3) * 3 ) + j][ ( ( (y - (y % 3) ) / 3)* 3 ) + k][z] == 1)
				{
				  flag = flag && (0 != 0);
				}
			    } /* done k */
			} /* done j */
		    }

		  /* Init */
		  sum_x = 0;
		  sum_y = 0;
		  sum_z = 0;
		  /* Calc Sum */
		  for(i = 0; i < 9; i++)
		    {
		      sum_x += V[i][y][z];
		      sum_y += V[x][i][z];
		      sum_z += V[x][y][i];
		    }
		  /* Calc Area Sum */
		  sum_area = 0;
		  for(i = 0; i < 3; i++)
		    {
		      for(j = 0; j < 3; j++)
			{
			  sum_area += V[ ( ( (x - (x % 3)) / 3) * 3 ) + i][ ( ( (y - (y % 3) ) / 3)* 3 ) + j][z];
			} /* done j */
		    } /* done i */

		  /* Check Phase.1 */
		  h = 0;
		  conf = 1;
		  if(sum_x == 0){
		    h++;
		  } /* fi */
		  if(sum_y == 0){
		    h++;
		  } /* fi */
		  if(sum_z == 0){
		    h++;
		  } /* fi */
		  if(sum_area == 0){
		    h++;
		  } /* fi */

		  if( (sum_x + sum_y + sum_z == 3) && sum_area == 1)
		    {
		      conf = 0;
		      //continue;
		    }
		  //printf("%d,%d,%d,%d\n", sum_x, sum_y, sum_z, sum_area);

		  U[x][y][z] =
		    U[x][y][z] -
		    var_1 * (sum_x + sum_y + sum_z - 3) -
		    var_2 * (sum_area) +
		    var_3 * 1;

		  if(U[x][y][z] > MAX_LIMIT){
		    U[x][y][z] = MAX_LIMIT;
		  } /* fi */
		  if(U[x][y][z] < -MAX_LIMIT){
		    U[x][y][z] = -MAX_LIMIT;
		  } /* fi */

		  if(U[x][y][z] > 0){
		    n = 0;
		    for(i = 0; i < 9; i++){
		      n += Vm[x][y][i];	
		    }
		    if(n == 0 && flag){
		      V[x][y][z] = 1;
		    }
		  }
		  else{
		    if(Vm[x][y][z] != 1){
		      V[x][y][z] = 0;
		    }
		  } /* fi */

		  diag = diag + conf;
		} /* done x */
	    } /* done y */
	} /* done z */

      /* Next Phase Prepere Process */
      phase_count++;
      if( (phase_count % 15) < 5)
	{
	  var_3 = NUM_3_2;
	}
      else
	{
	  var_3 = NUM_3;
	}
    } /* done */

  /* Result */
  printf("Phase: %d Steps\n", phase_count);

  disp();

  return(0x00);
}
