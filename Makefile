test:
	sage -t src/civerly

test-%:
	sage -t --optional=sage,$* --long src/civerly

test-no-gurobi:
	sage -t --optional=sage,scip,glpk,espresso,cadical,cryptominisat --long src/civerly
