/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "architecture.hh"
#include "funcdata.hh"
#include "ruleaction.hh"
#include "test.hh"

namespace ghidra {

class RuleActionTestEnvironment {
  Architecture *g;
  uintb nextFunctionAddr;
public:
  RuleActionTestEnvironment(void);
  ~RuleActionTestEnvironment(void);
  void build(void);
  Funcdata *newFunction(void);
};

static RuleActionTestEnvironment theEnviron;

RuleActionTestEnvironment::RuleActionTestEnvironment(void)

{
  g = (Architecture *)0;
  nextFunctionAddr = 0x1000;
}

RuleActionTestEnvironment::~RuleActionTestEnvironment(void)

{
  if (g != (Architecture *)0)
    delete g;
}

void RuleActionTestEnvironment::build(void)

{
  if (g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  g = xmlCapability->buildArchitecture("", "", &cout);
  g->init(store);
}

Funcdata *RuleActionTestEnvironment::newFunction(void)

{
  Address addr(g->getDefaultCodeSpace(),nextFunctionAddr);
  nextFunctionAddr += 0x10;
  return g->symboltab->getGlobalScope()->addFunction(addr,"rule_action_test")->getFunction();
}

static PcodeOp *buildProducer(Funcdata *data,const Address &addr,Varnode *&out)

{
  PcodeOp *op = data->newOp(2,addr);
  out = data->newUniqueOut(4,op);
  data->opSetOpcode(op,CPUI_INT_ADD);
  data->opSetInput(op,data->newConstant(4,5),0);
  data->opSetInput(op,data->newConstant(4,3),1);
  return op;
}

static PcodeOp *buildCopy(Funcdata *data,const Address &addr,Varnode *src,Varnode *&out)

{
  PcodeOp *op = data->newOp(1,addr);
  out = data->newUniqueOut(4,op);
  data->opSetOpcode(op,CPUI_COPY);
  data->opSetInput(op,src,0);
  return op;
}

static void buildUse(Funcdata *data,const Address &addr,Varnode *src)

{
  PcodeOp *op = data->newOp(1,addr);
  data->newUniqueOut(4,op);
  data->opSetOpcode(op,CPUI_INT_NEGATE);
  data->opSetInput(op,src,0);
}

TEST(fold_temporary) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1000);
  Varnode *src;
  PcodeOp *producer = buildProducer(data,addr,src);
  Varnode *dest;
  PcodeOp *copy = buildCopy(data,addr,src,dest);
  buildUse(data,addr,dest);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(copy,*data),1);
  ASSERT(producer->getOut() == dest);
  ASSERT(dest->getDef() == producer);
  ASSERT(copy->getOut() == (Varnode *)0);
  ASSERT(src->isFree());
  ASSERT(src->hasNoDescend());
}

TEST(fold_temporary_chain) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1010);
  Varnode *src;
  PcodeOp *producer = buildProducer(data,addr,src);
  Varnode *middle;
  PcodeOp *firstCopy = buildCopy(data,addr,src,middle);
  Varnode *dest;
  PcodeOp *secondCopy = buildCopy(data,addr,middle,dest);
  buildUse(data,addr,dest);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(firstCopy,*data),1);
  ASSERT_EQUALS(rule.applyOp(secondCopy,*data),1);
  ASSERT(producer->getOut() == dest);
  ASSERT(dest->getDef() == producer);
  ASSERT(src->isFree());
  ASSERT(middle->isFree());
}

TEST(fold_temporary_dead_destination) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1020);
  Varnode *src;
  buildProducer(data,addr,src);
  Varnode *dest;
  PcodeOp *copy = buildCopy(data,addr,src,dest);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(copy,*data),0);
  ASSERT(copy->getOut() == dest);
}

TEST(fold_temporary_multiple_uses) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1030);
  Varnode *src;
  buildProducer(data,addr,src);
  Varnode *dest;
  PcodeOp *copy = buildCopy(data,addr,src,dest);
  buildUse(data,addr,src);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(copy,*data),0);
  ASSERT(copy->getOut() == dest);
}

TEST(fold_temporary_non_temporary_source) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1040);
  Varnode *dest;
  PcodeOp *copy = buildCopy(data,addr,data->newConstant(4,7),dest);
  buildUse(data,addr,dest);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(copy,*data),0);
  ASSERT(copy->getOut() == dest);
}

TEST(fold_temporary_self_reference) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1050);
  PcodeOp *producer = data->newOp(2,addr);
  Varnode *src = data->newUniqueOut(4,producer);
  data->opSetOpcode(producer,CPUI_INT_ADD);
  Varnode *dest = data->newUnique(4);
  data->opSetInput(producer,dest,0);
  data->opSetInput(producer,data->newConstant(4,1),1);
  PcodeOp *copy = data->newOp(1,addr);
  data->opSetOutput(copy,dest);
  data->opSetOpcode(copy,CPUI_COPY);
  data->opSetInput(copy,src,0);
  buildUse(data,addr,dest);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(copy,*data),0);
  ASSERT(producer->getOut() == src);
}

TEST(fold_temporary_return_copy) {
  theEnviron.build();
  Funcdata *data = theEnviron.newFunction();
  Address addr(data->getArch()->getDefaultCodeSpace(),0x1060);
  Varnode *src;
  buildProducer(data,addr,src);
  Varnode *dest;
  PcodeOp *copy = buildCopy(data,addr,src,dest);
  data->markReturnCopy(copy);
  buildUse(data,addr,dest);

  RuleFoldTemporary rule("analysis");
  ASSERT_EQUALS(rule.applyOp(copy,*data),0);
  ASSERT(copy->getOut() == dest);
}

} // End namespace ghidra
