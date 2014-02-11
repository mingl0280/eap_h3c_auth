#include <iostream>

using namespace std;

int main()
{
    int a=0;
    cout<<"Input A:";
    cin>>a;
    int b[a];
    for (int i=0;i<a;i++)cin>>b[i];
    for (int j=a;j>0;j--)cout<<b[j-1];
    return 0;
}
