using Amazon.Lambda.Core;
using System;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Namespace
{
    public class Handler
    {
       public JObject FunctionHandler(JObject input)
       {
           return input;
       }
    }
}