class test
{
public:
    test() = default;
    virtual ~test() = default;
};

int main()
{
    test *t = new test();

    return 0;
}