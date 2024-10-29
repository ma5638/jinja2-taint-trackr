import jsql, ctx

class X: ...

class A:
    monkey = X()

    def ex(self):
        # setattr(self.monkey,'id', ctx.mp)
        self.monkey.id = ctx.mp
        self.execute()
    
    def execute(self):
        pass

class B(A):
    def execute(self):
        jsql.sql(f"SELECT = {self.monkey.id}")