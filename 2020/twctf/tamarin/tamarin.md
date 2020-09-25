# Tamarin

An apk file was given by the challenge author. It can be unpacked using 7zip. Inside is a library called `libmonodroid_bundle_app.so` it can be unpacked using [Mono Unbundle](https://github.com/tjg1/mono_unbundle). The unpacked dlls contain `Tamarin.dll`, which can be decompiled using [dnSpy](https://github.com/0xd4d/dnSpy).
```csharp
[...]
public static bool Func4 (string flag) {
    ParallelOptions parallelOptions = new ParallelOptions {
        MaxDegreeOfParallelism = 4
    };
    byte[] bytes = Encoding.ASCII.GetBytes (flag);
    int length = flag.Length;
    if ((length & 3) != 0) {
        Array.Resize<byte> (ref bytes, length + (4 - (length & 3)));
    }
    for (int i = length; i < bytes.Length; i++) {
        bytes[i] = 0;
    }
    if (bytes.Length != Check.equations_arr.GetLength (0) * 4) {
        return false;
    }
    object lockObj = new object ();
    ConcurrentBag<bool> checkResults = new ConcurrentBag<bool> ();
    List<List<uint>> list = new List<List<uint>> ();
    for (int j = 0; j < Check.equations_arr.GetLength (0); j++) {
        List<uint> list2 = new List<uint> ();
        list2.Add (BitConverter.ToUInt32 (bytes, j * 4));
        for (int k = 0; k < Check.equations_arr.GetLength (1); k++) {
            list2.Add (Check.equations_arr[j, k]);
        }
        list.Add (list2);
    }
    Parallel.ForEach<List<uint>> (list, parallelOptions, delegate (List<uint> equation) {
        lock (lockObj) {
            uint num = Check.Func3 ();
            for (int l = 0; l < 10000; l++) {
                num = Check.CreatePoly (equation, num, equation.Count - 2);
            }
            checkResults.Add (num == equation[equation.Count - 1]);
        }
    });
    return checkResults.ToArray ().All ((bool x) => x);
}
[...]
```

The function `Func4` returns `true` if we give it the flag as input. The function checks for groups of 4 bytes if the input solves some Polynomial equation. I watched the `num` variable while changing the input bytes, every group is independent and if we change the lower bytes of the input they don't change the upper ones of the output. This allows for a brute-force in O(n*4) instead of O(n^4).

And it outputs the flag that needs to be wrapped inside the format:
```
First
Second
Third
Last
0
Xm4r
[...]
0,90909094
Xm4r1n_15_4bl3_70_6en3r4t3_N471v3_C0d3_w17h_VS_3n73rpr153_bu7_17_c0n741n5_D07_N3t_B1
First
Second
Third
Last
0,95454544
Xm4r1n_15_4bl3_70_6en3r4t3_N471v3_C0d3_w17h_VS_3n73rpr153_bu7_17_c0n741n5_D07_N3t_B1n4ry
```

## Solve script

```cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualBasic.CompilerServices;

namespace Core
{
	// Token: 0x02000004 RID: 4

	public static class Check
	{
		static void Main(string[] args)
		{

			uint ret = 0;
			uint o = 0;
			uint inp = 0;
			string pp = "";
			for (int n = 0; n < Check.equations_arr.GetLength(0); n += 1)
			{

				uint l = 0;
				for (; l < 255; l += 1)
				{
					inp = (l << 0);
					ret = Dooo(n, inp);
					o = Check.equations_arr[n, Check.equations_arr.GetLength(1) - 1];
					if (((o & 0xFF) == (ret & 0xFF)))
					{
						Console.WriteLine("First");
						break;
					}
				}
				uint k = 0;
				for (; k < 255; k += 1)
				{
					inp = (l << 0) | (k << 8);
					ret = Dooo(n, inp);
					o = Check.equations_arr[n, Check.equations_arr.GetLength(1) - 1];
					if ((o & 0xFFFF) == (ret & 0xFFFF))
					{
						Console.WriteLine("Second");
						break;
					}
				}
				uint j = 0;
				for (; j < 255; j += 1)
				{
					inp = (l << 0) | (k << 8) | (j << 16);
					ret = Dooo(n, inp);
					o = Check.equations_arr[n, Check.equations_arr.GetLength(1) - 1];

					if (((o & 0xFFFFFF) == (ret & 0xFFFFFF)))
					{
						Console.WriteLine("Third");
						break;
					}
				}
				uint i = 0;
				for (; i < 255; i += 1)
				{
					inp = (l << 0) | (k << 8) | (j << 16) | (i << 24);
					ret = Dooo(n, inp);
					o = Check.equations_arr[n, Check.equations_arr.GetLength(1) - 1];
					if (((o) == (ret)))
					{
						Console.WriteLine("Last");
						break;
					}
				}
				Console.WriteLine((float)n / Check.equations_arr.GetLength(0));
				pp += Encoding.ASCII.GetString(BitConverter.GetBytes(inp));
				Console.WriteLine(pp);
			}
			
		}
		// Token: 0x06000007 RID: 7 RVA: 0x00002764 File Offset: 0x00000964
		private static uint Exp(uint x, int n)
		{
			uint num = 1U;
			for (int i = 0; i < n; i++)
			{
				num *= x;
			}
			return num;
		}

		// Token: 0x06000008 RID: 8 RVA: 0x00002784 File Offset: 0x00000984
		private static uint CreatePoly(List<uint> coefficients, uint x, int pos)
		{
			if (pos == -1)
			{
				return 0U;
			}
			uint num = coefficients[pos] * Check.Exp(x, pos);
			return num + Check.CreatePoly(coefficients, x, pos - 1);
		}

		// Token: 0x06000009 RID: 9 RVA: 0x000027B8 File Offset: 0x000009B8
		private static uint Func3()
		{
			byte[] array = new byte[4];
			using (RNGCryptoServiceProvider rngcryptoServiceProvider = new RNGCryptoServiceProvider())
			{
				rngcryptoServiceProvider.GetBytes(array);
			}
			return BitConverter.ToUInt32(array, 0);
		}

		// Token: 0x0600000A RID: 10 RVA: 0x000027FC File Offset: 0x000009FC
		public static bool Func4(string flag)
		{
			ParallelOptions parallelOptions = new ParallelOptions
			{
				MaxDegreeOfParallelism = 4
			};
			byte[] bytes = Encoding.ASCII.GetBytes(flag);
			int length = flag.Length;
			if ((length & 3) != 0)
			{
				Array.Resize<byte>(ref bytes, length + (4 - (length & 3)));
			}
			for (int i = length; i < bytes.Length; i++)
			{
				bytes[i] = 0;
			}
			if (bytes.Length != Check.equations_arr.GetLength(0) * 4)
			{
				return false;
			}
			object lockObj = new object();
			ConcurrentBag<bool> checkResults = new ConcurrentBag<bool>();
			List<List<uint>> list = new List<List<uint>>();
			for (int j = 0; j < Check.equations_arr.GetLength(0); j++)
			{
				List<uint> list2 = new List<uint>();
				list2.Add(BitConverter.ToUInt32(bytes, j * 4));
				for (int k = 0; k < Check.equations_arr.GetLength(1); k++)
				{
					list2.Add(Check.equations_arr[j, k]);
				}
				list.Add(list2);
			}
			Parallel.ForEach<List<uint>>(list, parallelOptions, delegate (List<uint> equation)
			{
				lock (lockObj)
				{
					uint num = Check.Func3();
					for (int l = 0; l < 10000; l++)
					{
						num = Check.CreatePoly(equation, num, equation.Count - 2);
					}
					checkResults.Add(num == equation[equation.Count - 1]);
				}
			});
			return checkResults.ToArray().All((bool x) => x);
		}


		public static uint Dooo(int n, uint p)
		{
			List<uint> list2 = new List<uint>();
			list2.Add(p);
			for (int k = 0; k < Check.equations_arr.GetLength(1); k++)
			{
				list2.Add(Check.equations_arr[n, k]);
			}
			
			
			uint num = Check.Func3();
			for (int l = 0; l < 10000; l++)
			{
				num = Check.CreatePoly(list2, num, list2.Count - 2);
			}
			return num;
		}


		// Token: 0x04000001 RID: 1
		private static readonly uint[,] equations_arr = new uint[,]
		{
			{
				2921822136U,
				1060277104U,
				2035740900U,
				823622198U,
				210968592U,
				3474619224U,
				3252966626U,
				1671622480U,
				1174723606U,
				3830387194U,
				2514889364U,
				3125636774U,
				896423784U,
				4164953836U,
				2838119626U,
				2523117444U,
				1385864710U,
				3157438448U,
				132542958U,
				4108218268U,
				314662132U,
				432653936U,
				1147047258U,
				1802950730U,
				67411056U,
				1207641174U,
				1920298940U,
				2947533900U,
				3468512014U,
				3485949926U,
				3695085832U,
				3903653528U
			},
			{
				463101660U,
				3469888460U,
				2006842986U,
				144738028U,
				630007230U,
				3440652086U,
				2322916652U,
				2227002010U,
				1163469256U,
				23859328U,
				2322597530U,
				3716255122U,
				2876706098U,
				713374856U,
				2345958624U,
				3496771192U,
				1773957550U,
				146382778U,
				1141367704U,
				1061893394U,
				994321632U,
				3407332344U,
				2240786438U,
				2218631702U,
				2906647610U,
				1919308420U,
				2136654012U,
				164975906U,
				2834189362U,
				3118478912U,
				3258673870U,
				3211411825U
			},
			{
				2558729100U,
				1170420958U,
				2355877954U,
				3593652986U,
				2587766164U,
				2271696650U,
				1560549496U,
				132089692U,
				2893757564U,
				3469624876U,
				10109206U,
				2948199026U,
				4170042296U,
				2717317064U,
				4210960804U,
				93756380U,
				2006217436U,
				2988057920U,
				2251383150U,
				226355976U,
				579516546U,
				3915017586U,
				1273838010U,
				2852178952U,
				4272774672U,
				1006507228U,
				3595131622U,
				1880597220U,
				1230996622U,
				2542910224U,
				917668128U,
				1612363977U
			},
			{
				3637139654U,
				2593663532U,
				649194106U,
				4275630476U,
				2730487128U,
				905133820U,
				2868808700U,
				1284610026U,
				1051455306U,
				272375560U,
				1219428572U,
				163965224U,
				3899483864U,
				309833108U,
				1862243284U,
				1919038730U,
				3414916994U,
				3134382762U,
				2018925234U,
				3467081876U,
				4045123308U,
				4244105094U,
				4205568254U,
				1793827648U,
				257732384U,
				2092183712U,
				3517540150U,
				2641565070U,
				2181538960U,
				2670634300U,
				2070334778U,
				1995308868U
			},
			{
				561434200U,
				2730097174U,
				1499965472U,
				760244614U,
				1588114416U,
				521516362U,
				2963707630U,
				1896166800U,
				411250470U,
				1601999958U,
				2973942456U,
				3027806424U,
				1238337602U,
				1380721280U,
				122976200U,
				788897864U,
				3589391734U,
				1987301254U,
				1085198712U,
				3553616586U,
				1994354546U,
				1684916442U,
				2788234788U,
				2641884090U,
				612801768U,
				1801824798U,
				2019943314U,
				3304068906U,
				849354132U,
				44941780U,
				3473262708U,
				1444837808U
			},
			{
				921974086U,
				404262832U,
				1353817916U,
				764855648U,
				2290476820U,
				2023815980U,
				669786172U,
				791841140U,
				526348842U,
				2979022342U,
				3656325786U,
				1276970440U,
				2424614726U,
				1190814714U,
				2804417116U,
				3654263826U,
				3068580996U,
				1908493640U,
				3101330462U,
				792198672U,
				1772484794U,
				4050408722U,
				611660842U,
				1610808360U,
				431629552U,
				2319897718U,
				3255085210U,
				1426503472U,
				1630566802U,
				4241881448U,
				1606014350U,
				636517450U
			},
			{
				2906103140U,
				1116553354U,
				2279536366U,
				3011561210U,
				2641603848U,
				1646150780U,
				192124694U,
				611421916U,
				3416039786U,
				4208848404U,
				474397384U,
				1491088256U,
				3177553844U,
				2042765300U,
				1653674858U,
				1365840538U,
				1595225706U,
				2705938552U,
				3180386458U,
				1723055560U,
				2280421090U,
				1241156010U,
				3807390206U,
				2595800854U,
				2890507242U,
				4068903400U,
				3923234634U,
				2613933834U,
				3927909200U,
				2149793556U,
				3589302752U,
				802516900U
			},
			{
				171242408U,
				1411016272U,
				2890085382U,
				624162464U,
				3117870816U,
				3388454296U,
				3869111620U,
				948964384U,
				1670102044U,
				3432346180U,
				1670460686U,
				3674313702U,
				4108083090U,
				915550832U,
				4249135230U,
				411447682U,
				2915987712U,
				3865207952U,
				4017666788U,
				275767786U,
				2506858524U,
				3488718446U,
				1995975410U,
				566166116U,
				1590333384U,
				329205954U,
				3913164274U,
				620615436U,
				1464604756U,
				269837028U,
				963851056U,
				2483789524U
			},
			{
				4043184956U,
				3569779124U,
				3817645374U,
				4281618348U,
				4144074366U,
				3776223584U,
				2260112022U,
				2417238210U,
				4004384546U,
				1196429850U,
				1429697170U,
				3075499898U,
				2507660230U,
				1342925724U,
				3951341456U,
				229184726U,
				2762396986U,
				1612961426U,
				986238002U,
				1228690306U,
				3948701236U,
				1378190546U,
				3106898794U,
				1894874158U,
				1488049036U,
				3718233910U,
				1078939754U,
				2355898312U,
				2030934192U,
				2879370894U,
				3017715248U,
				1647621107U
			},
			{
				3849716376U,
				3412391848U,
				420800182U,
				156925722U,
				3602232204U,
				2645326622U,
				3864083570U,
				1279782822U,
				878821008U,
				1906288878U,
				1396282244U,
				1641728726U,
				2295751090U,
				290937256U,
				1958396986U,
				2115100470U,
				3706945590U,
				2885002942U,
				1935777480U,
				1483762940U,
				3589264430U,
				3791465274U,
				2553819596U,
				2050180502U,
				1381704584U,
				4640270U,
				628970046U,
				774725214U,
				2575508070U,
				1330692832U,
				1250987676U,
				3756982724U
			},
			{
				1460953346U,
				1175847424U,
				3477700838U,
				3783709768U,
				1064663570U,
				3559971784U,
				3802954664U,
				2431960456U,
				2198986400U,
				859802318U,
				3783810034U,
				1110187920U,
				4244034440U,
				1796543058U,
				902449590U,
				160031782U,
				3639253664U,
				4255746326U,
				3339514496U,
				218988706U,
				4085181614U,
				2342973726U,
				1391523108U,
				1120970708U,
				2639842372U,
				156321138U,
				1587974922U,
				3686627774U,
				1648124740U,
				2095688044U,
				293533614U,
				3056924137U
			},
			{
				1034259104U,
				4077045412U,
				789979418U,
				961028604U,
				2185949320U,
				3457364068U,
				3532291848U,
				2206594748U,
				3072062072U,
				1796530288U,
				1402389280U,
				3478769990U,
				196567236U,
				3940435298U,
				2237679842U,
				668941406U,
				170819894U,
				1102049112U,
				131349762U,
				2512464482U,
				4159048294U,
				2186098090U,
				123947608U,
				1742064290U,
				1711289746U,
				1449132362U,
				58078952U,
				2976574968U,
				1774398264U,
				1532589156U,
				4089484268U,
				4041979478U
			},
			{
				3681899832U,
				4208608358U,
				1951338724U,
				3772673566U,
				3160075610U,
				1422174080U,
				2431526454U,
				529884656U,
				2722748162U,
				236192616U,
				2684139926U,
				697549902U,
				3546454434U,
				1921398338U,
				1310272304U,
				1691292498U,
				4134700116U,
				720619430U,
				2592536546U,
				2188997288U,
				2461521148U,
				455077540U,
				1421274126U,
				1052585740U,
				2383754190U,
				1567602170U,
				3773864138U,
				4036579298U,
				2416620860U,
				1931099884U,
				2051263696U,
				310763286U
			},
			{
				1461705722U,
				968835462U,
				2563821358U,
				576185928U,
				1613137824U,
				940353300U,
				652295412U,
				1135005196U,
				3607866196U,
				3307698550U,
				3916080186U,
				4052934590U,
				3991167852U,
				3799175976U,
				3393348946U,
				950814766U,
				2174463160U,
				2422320256U,
				959545514U,
				2820210140U,
				4284041840U,
				3082466322U,
				1257510060U,
				2676710840U,
				127465314U,
				3887977956U,
				3218198116U,
				957094088U,
				1409365960U,
				2217798938U,
				277108032U,
				2579736592U
			},
			{
				3776055232U,
				823459706U,
				1913270776U,
				1721511850U,
				633354432U,
				3901765934U,
				2089017122U,
				1103648570U,
				3791238880U,
				1686042442U,
				1567720048U,
				2924815412U,
				1695861754U,
				3641036796U,
				1208391908U,
				1593134050U,
				1674288590U,
				2322785248U,
				2472109738U,
				3572933674U,
				3828029068U,
				1641647380U,
				4116180236U,
				3884220004U,
				3146594508U,
				3587030908U,
				3451856524U,
				2965945264U,
				162291656U,
				2061732942U,
				1551591510U,
				4014200221U
			},
			{
				3406794856U,
				3181753846U,
				2984888850U,
				1748566984U,
				1311737108U,
				3415409722U,
				2398926736U,
				2006269026U,
				3117725174U,
				2901254050U,
				2733703362U,
				1595001962U,
				106879068U,
				3933136528U,
				245096038U,
				666024082U,
				134803296U,
				1657783988U,
				3429228290U,
				2120419114U,
				2879013028U,
				9653606U,
				305704628U,
				3793128986U,
				369835124U,
				2274924880U,
				4233339440U,
				2224753480U,
				2427854922U,
				1808326540U,
				1833703938U,
				2391461119U
			},
			{
				1827597388U,
				454565514U,
				1282880792U,
				561174442U,
				3610484436U,
				2327669348U,
				765794442U,
				3705161518U,
				1715916192U,
				292859360U,
				183730846U,
				3298097994U,
				3535037218U,
				2904849282U,
				348832662U,
				1856773750U,
				3618335118U,
				3017093112U,
				3354956190U,
				3208811970U,
				897522204U,
				2835584374U,
				3097985334U,
				2108903166U,
				3230714490U,
				2597789348U,
				1597521406U,
				1663858876U,
				94923994U,
				883872856U,
				3230397040U,
				3420763893U
			},
			{
				4065160224U,
				2129787468U,
				3456903512U,
				2860656238U,
				2663588170U,
				3224900102U,
				2827778318U,
				2685874320U,
				2005737334U,
				586304716U,
				472376412U,
				2938324550U,
				3459137716U,
				3422216092U,
				3082124658U,
				1173945064U,
				842495374U,
				2564495050U,
				357433170U,
				2050324102U,
				1138367532U,
				854845936U,
				3054001576U,
				2465772674U,
				2305389082U,
				3669610606U,
				3527889292U,
				3817664802U,
				4238531160U,
				1556372762U,
				777986002U,
				1126454981U
			},
			{
				764733144U,
				3965849612U,
				1668893328U,
				2104626056U,
				1653642872U,
				2883395356U,
				3015268318U,
				2322404760U,
				1185726976U,
				1607036694U,
				3064704530U,
				3639372768U,
				1252489394U,
				3950622630U,
				3889240956U,
				233990458U,
				2393973872U,
				3609439896U,
				2108036182U,
				152726882U,
				3730671578U,
				3038534682U,
				3388044150U,
				3128791454U,
				2499312664U,
				3396894570U,
				2872225186U,
				3048419004U,
				2864782986U,
				3169897264U,
				2890258816U,
				753842003U
			},
			{
				2403595118U,
				2093259638U,
				2763900156U,
				3772789760U,
				3282639530U,
				2884294140U,
				3879894514U,
				2512089226U,
				318451120U,
				2464691316U,
				2179668204U,
				795049786U,
				326585310U,
				1313213364U,
				3437852224U,
				4055872768U,
				1224395344U,
				1911910472U,
				983774674U,
				3804144712U,
				3208317764U,
				1534290234U,
				3243577720U,
				617743358U,
				378252266U,
				3612369740U,
				1924240610U,
				961715850U,
				2058485164U,
				1460892148U,
				2613095898U,
				73199927U
			},
			{
				3093631524U,
				2704600210U,
				3519611266U,
				5414320U,
				3358912704U,
				2462642760U,
				3764896542U,
				1253645320U,
				4034052234U,
				3137650284U,
				4083324920U,
				2667059126U,
				436316958U,
				497182460U,
				404768030U,
				1122443700U,
				432434942U,
				443290780U,
				3487257114U,
				2699955512U,
				4250049274U,
				3991832458U,
				1037538700U,
				3125332984U,
				1533312690U,
				1452437348U,
				1283257518U,
				3946567854U,
				716640500U,
				2417637998U,
				3063327834U,
				82885668U
			},
			{
				1985108U,
				1694522756U,
				4205785758U,
				333118606U,
				2944637686U,
				2196892858U,
				4092971632U,
				83374602U,
				4049383084U,
				2980843496U,
				1801648602U,
				2639009750U,
				1944350566U,
				3046229260U,
				2662687100U,
				2423732014U,
				4179240348U,
				1035280058U,
				1015236846U,
				3488976898U,
				1530833166U,
				3723596058U,
				4125718292U,
				1095267878U,
				3635353922U,
				2932904358U,
				2764606674U,
				45921060U,
				3107074868U,
				4198045636U,
				1923836480U,
				366302822U
			}
		};
	}
	
}
```

## Flag
```
TWCTF{Xm4r1n_15_4bl3_70_6en3r4t3_N471v3_C0d3_w17h_VS_3n73rpr153_bu7_17_c0n741n5_D07_N3t_B1n4ry}```